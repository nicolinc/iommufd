// SPDX-License-Identifier: GPL-2.0
/*
 * Helpers for IOMMU drivers implementing SVA
 */
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/iommu.h>

#include "iommu-sva.h"

static DEFINE_MUTEX(iommu_sva_lock);

/**
 * iommu_sva_alloc_pasid - Allocate a PASID for the mm
 * @mm: the mm
 * @min: minimum PASID value (inclusive)
 * @max: maximum PASID value (inclusive)
 *
 * Try to allocate a PASID for this mm, or take a reference to the existing one
 * provided it fits within the [@min, @max] range. On success the PASID is
 * available in mm->pasid and will be available for the lifetime of the mm.
 *
 * Returns 0 on success and < 0 on error.
 */
int iommu_sva_alloc_pasid(struct mm_struct *mm, ioasid_t min, ioasid_t max)
{
	int ret = 0;
	ioasid_t pasid;

	if (min == INVALID_IOASID || max == INVALID_IOASID ||
	    min == 0 || max < min)
		return -EINVAL;

	mutex_lock(&iommu_sva_lock);
	/* Is a PASID already associated with this mm? */
	if (pasid_valid(mm->pasid)) {
		if (mm->pasid < min || mm->pasid >= max)
			ret = -EOVERFLOW;
		goto out;
	}

	pasid = ioasid_alloc(NULL, min, max, mm, 0);
	if (!pasid_valid(pasid))
		ret = -ENOMEM;
	else
		mm_pasid_set(mm, pasid);
out:
	mutex_unlock(&iommu_sva_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(iommu_sva_alloc_pasid);

/* ioasid_find getter() requires a void * argument */
static bool __mmget_not_zero(void *mm)
{
	return mmget_not_zero(mm);
}

/**
 * iommu_sva_find() - Find mm associated to the given PASID
 * @pasid: Process Address Space ID assigned to the mm
 *
 * On success a reference to the mm is taken, and must be released with mmput().
 *
 * Returns the mm corresponding to this PASID, or an error if not found.
 */
struct mm_struct *iommu_sva_find(ioasid_t pasid)
{
	return ioasid_find(NULL, pasid, __mmget_not_zero);
}
EXPORT_SYMBOL_GPL(iommu_sva_find);

/**
 * iommu_sva_bind_device() - Bind a process address space to a device
 * @dev: the device
 * @mm: the mm to bind, caller must hold a reference to mm_users
 *
 * Create a bond between device and address space, allowing the device to access
 * the mm using the returned PASID. If a bond already exists between @device and
 * @mm, it is returned and an additional reference is taken. Caller must call
 * iommu_sva_unbind_device() to release each reference.
 *
 * iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA) must be called first, to
 * initialize the required SVA features.
 *
 * On error, returns an ERR_PTR value.
 */
struct iommu_sva *iommu_sva_bind_device(struct device *dev, struct mm_struct *mm)
{
	struct iommu_domain *domain;
	ioasid_t max_pasids;
	int ret = -EINVAL;

	max_pasids = dev->iommu->max_pasids;
	if (!max_pasids)
		return ERR_PTR(-EOPNOTSUPP);

	/* Allocate mm->pasid if necessary. */
	ret = iommu_sva_alloc_pasid(mm, 1, max_pasids - 1);
	if (ret)
		return ERR_PTR(ret);

	mutex_lock(&iommu_sva_lock);
	/* Search for an existing domain. */
	domain = iommu_get_domain_for_dev_pasid(dev, mm->pasid);
	if (domain) {
		refcount_inc(&domain->bond.users);
		goto out_success;
	}

	/* Allocate a new domain and set it on device pasid. */
	domain = iommu_sva_domain_alloc(dev, mm);
	if (!domain) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	ret = iommu_attach_device_pasid(domain, dev, mm->pasid);
	if (ret)
		goto out_free_domain;
	domain->bond.dev = dev;
	refcount_set(&domain->bond.users, 1);

out_success:
	mutex_unlock(&iommu_sva_lock);
	return &domain->bond;

out_free_domain:
	iommu_domain_free(domain);
out_unlock:
	mutex_unlock(&iommu_sva_lock);

	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(iommu_sva_bind_device);

/**
 * iommu_sva_unbind_device() - Remove a bond created with iommu_sva_bind_device
 * @handle: the handle returned by iommu_sva_bind_device()
 *
 * Put reference to a bond between device and address space. The device should
 * not be issuing any more transaction for this PASID. All outstanding page
 * requests for this PASID must have been flushed to the IOMMU.
 */
void iommu_sva_unbind_device(struct iommu_sva *handle)
{
	struct device *dev = handle->dev;
	struct iommu_domain *domain =
			container_of(handle, struct iommu_domain, bond);
	ioasid_t pasid = iommu_sva_get_pasid(handle);

	mutex_lock(&iommu_sva_lock);
	if (refcount_dec_and_test(&domain->bond.users)) {
		iommu_detach_device_pasid(domain, dev, pasid);
		iommu_domain_free(domain);
	}
	mutex_unlock(&iommu_sva_lock);
}
EXPORT_SYMBOL_GPL(iommu_sva_unbind_device);

u32 iommu_sva_get_pasid(struct iommu_sva *handle)
{
	struct iommu_domain *domain =
			container_of(handle, struct iommu_domain, bond);

	return domain->mm->pasid;
}
EXPORT_SYMBOL_GPL(iommu_sva_get_pasid);

/*
 * I/O page fault handler for SVA
 */
enum iommu_page_response_code
iommu_sva_handle_iopf(struct iommu_fault *fault, struct device *dev, void *data)
{
	vm_fault_t ret;
	struct vm_area_struct *vma;
	struct mm_struct *mm = data;
	unsigned int access_flags = 0;
	unsigned int fault_flags = FAULT_FLAG_REMOTE;
	struct iommu_fault_page_request *prm = &fault->prm;
	enum iommu_page_response_code status = IOMMU_PAGE_RESP_INVALID;

	if (!(prm->flags & IOMMU_FAULT_PAGE_REQUEST_PASID_VALID))
		return status;

	if (IS_ERR_OR_NULL(mm) || !mmget_not_zero(mm))
		return status;

	mmap_read_lock(mm);

	vma = find_extend_vma(mm, prm->addr);
	if (!vma)
		/* Unmapped area */
		goto out_put_mm;

	if (prm->perm & IOMMU_FAULT_PERM_READ)
		access_flags |= VM_READ;

	if (prm->perm & IOMMU_FAULT_PERM_WRITE) {
		access_flags |= VM_WRITE;
		fault_flags |= FAULT_FLAG_WRITE;
	}

	if (prm->perm & IOMMU_FAULT_PERM_EXEC) {
		access_flags |= VM_EXEC;
		fault_flags |= FAULT_FLAG_INSTRUCTION;
	}

	if (!(prm->perm & IOMMU_FAULT_PERM_PRIV))
		fault_flags |= FAULT_FLAG_USER;

	if (access_flags & ~vma->vm_flags)
		/* Access fault */
		goto out_put_mm;

	ret = handle_mm_fault(vma, prm->addr, fault_flags, NULL);
	status = ret & VM_FAULT_ERROR ? IOMMU_PAGE_RESP_INVALID :
		IOMMU_PAGE_RESP_SUCCESS;

out_put_mm:
	mmap_read_unlock(mm);
	mmput(mm);

	return status;
}
