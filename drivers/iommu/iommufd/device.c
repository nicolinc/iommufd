// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommufd.h>
#include <linux/slab.h>
#include <linux/iommu.h>
#include <linux/file.h>
#include <linux/pci.h>
#include <linux/irqdomain.h>
#include <linux/dma-iommu.h>
#include <linux/dma-map-ops.h>

#include "iommufd_private.h"

struct iommufd_hwpt_device {
	ioasid_t pasid;
	struct iommufd_device *idev;
	struct iommufd_hw_pagetable *hwpt;
};

/*
 * A iommufd_device object represents the binding relationship between a
 * consuming driver and the iommufd. These objects are created/destroyed by
 * external drivers, not by userspace.
 */
struct iommufd_device {
	struct iommufd_object obj;
	struct iommufd_ctx *ictx;
	struct iommufd_hwpt_device *hdev;
	/* Head at iommufd_hw_pagetable::devices */
	struct list_head devices_item;
	/* always the physical device */
	struct device *dev;
	struct iommu_group *group;
	bool dma_owner_claimed;
};

struct iommufd_device_attach_data {
	unsigned int flags;
	ioasid_t pasid;
};

void iommufd_device_destroy(struct iommufd_object *obj)
{
	struct iommufd_device *idev =
		container_of(obj, struct iommufd_device, obj);

	if (idev->dma_owner_claimed)
		iommu_group_release_dma_owner(idev->group);
	iommu_group_put(idev->group);
	fput(idev->ictx->filp);
}

/**
 * iommufd_bind_device - Bind a physical device to an iommu fd
 * @fd: iommufd file descriptor.
 * @pdev: Pointer to a physical PCI device struct
 * @id: Output ID number to return to userspace for this device
 *
 * A successful bind establishes an ownership over the device and returns
 * struct iommufd_device pointer, otherwise returns error pointer.
 *
 * A driver using this API must set driver_managed_dma and must not touch
 * the device until this routine succeeds and establishes ownership.
 *
 * Binding a PCI device places the entire RID under iommufd control.
 *
 * The caller must undo this with iommufd_unbind_device()
 */
struct iommufd_device *iommufd_bind_device(int fd, struct device *dev,
					   unsigned int flags, u32 *id)
{
	struct iommufd_device *idev;
	struct iommufd_ctx *ictx;
	struct iommu_group *group;
	int rc;

       /*
        * iommufd always sets IOMMU_CACHE because we offer no way for userspace
        * to restore cache coherency.
        */
       if (!iommu_capable(dev->bus, IOMMU_CAP_CACHE_COHERENCY))
		return ERR_PTR(-EINVAL);

	ictx = iommufd_fget(fd);
	if (!ictx)
		return ERR_PTR(-EINVAL);

	group = iommu_group_get(dev);
	if (!group) {
		rc = -ENODEV;
		goto out_file_put;
	}

	/*
	 * FIXME: Use a device-centric iommu api and this won't work with
	 * multi-device groups
	 */
	if (!(flags & IOMMUFD_BIND_FLAGS_BYPASS_DMA_OWNERSHIP)) {
		rc = iommu_group_claim_dma_owner(group, ictx->filp);
		if (rc)
			goto out_group_put;
	}

	idev = iommufd_object_alloc(ictx, idev, IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(idev)) {
		rc = PTR_ERR(idev);
		goto out_release_owner;
	}
	idev->ictx = ictx;
	idev->dev = dev;
	idev->dma_owner_claimed =
		!(flags & IOMMUFD_BIND_FLAGS_BYPASS_DMA_OWNERSHIP);
	/* The calling driver is a user until iommufd_unbind_device() */
	refcount_inc(&idev->obj.users);
	/* group refcount moves into iommufd_device */
	idev->group = group;

	/*
	 * If the caller fails after this success it must call
	 * iommufd_unbind_device() which is safe since we hold this refcount.
	 * This also means the device is a leaf in the graph and no other object
	 * can take a reference on it.
	 */
	iommufd_object_finalize(ictx, &idev->obj);
	*id = idev->obj.id;
	return idev;

out_release_owner:
	if ((!flags & IOMMUFD_BIND_FLAGS_BYPASS_DMA_OWNERSHIP))
		iommu_group_release_dma_owner(group);
out_group_put:
	iommu_group_put(group);
out_file_put:
	fput(ictx->filp);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL_GPL(iommufd_bind_device);

void iommufd_unbind_device(struct iommufd_device *idev)
{
	bool was_destroyed;

	was_destroyed = iommufd_object_destroy_user(idev->ictx, &idev->obj);
	WARN_ON(!was_destroyed);
}
EXPORT_SYMBOL_GPL(iommufd_unbind_device);

int iommufd_device_get_info(struct iommufd_ucmd *ucmd)
{
	struct iommu_device_info *cmd = ucmd->cmd;
	struct iommufd_object *obj;
	struct iommufd_device *idev;
	struct iommu_hw_info hw_info;
	u32 user_length;
	int rc;

	if (cmd->flags || cmd->reserved || cmd->dev_id == IOMMUFD_INVALID_ID)
		return -EOPNOTSUPP;

	obj = iommufd_get_object(ucmd->ictx, cmd->dev_id, IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	idev = container_of(obj, struct iommufd_device, obj);

	rc = iommu_get_hw_info(idev->dev, &hw_info);
	if (rc < 0)
		goto out_put;

	cmd->iommu_hw_type = hw_info.type;

	if (hw_info.data_length <= cmd->hw_data_len &&
	    copy_to_user((void __user *)cmd->hw_data_ptr,
			 &hw_info.data, hw_info.data_length)) {
		rc = -EFAULT;
		goto out_put;
	}

	user_length = cmd->hw_data_len;
	cmd->hw_data_len = hw_info.data_length;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_put;

	if (hw_info.data_length > user_length) {
		rc = -EMSGSIZE;
	}

out_put:
	iommufd_put_object(obj);
	return rc;
}

static int iommufd_device_setup_msi(struct iommufd_device *idev,
				    struct iommufd_hw_pagetable *hwpt,
				    phys_addr_t sw_msi_start,
				    unsigned int flags)
{
	int rc;

	/*
	 * IOMMU_CAP_INTR_REMAP means that the platform is isolating MSI,
	 * nothing further to do.
	 */
	if (iommu_capable(idev->dev->bus, IOMMU_CAP_INTR_REMAP))
		return 0;

	/*
	 * On ARM systems that set the global IRQ_DOMAIN_FLAG_MSI_REMAP every
	 * allocated iommu_domain will block interrupts by default and this
	 * special flow is needed to turn them back on.
	 */
	if (irq_domain_check_msi_remap()) {
		if (WARN_ON(!sw_msi_start))
			return -EPERM;
		/*
		 * iommu_get_msi_cookie() can only be called once per domain,
		 * it returns -EBUSY on later calls.
		 */
		if (hwpt->msi_cookie)
			return 0;
		rc = iommu_get_msi_cookie(hwpt->domain, sw_msi_start);
		if (rc && rc != -ENODEV)
			return rc;
		hwpt->msi_cookie = true;
		return 0;
	}

	/*
	 * Otherwise the platform has a MSI window that is not isolated. For
	 * historical compat with VFIO allow a module parameter to ignore the
	 * insecurity.
	 */
	if (!(flags & IOMMUFD_ATTACH_FLAGS_ALLOW_UNSAFE_INTERRUPT))
		return -EPERM;
	return 0;
}

static bool iommufd_hw_pagetable_has_group(struct iommufd_hw_pagetable *hwpt,
					   struct iommu_group *group)
{
	struct iommufd_device *cur_dev;

	list_for_each_entry (cur_dev, &hwpt->devices, devices_item)
		if (cur_dev->group == group)
			return true;
	return false;
}

static int device_attach_auto_hwpt(struct iommufd_device *idev,
				   struct iommufd_hw_pagetable *hwpt,
				   unsigned int flags)
{
	phys_addr_t sw_msi_start = 0;
	int rc;

	/*
	 * hwpt is now the exclusive owner of the group so this is the
	 * first time enforce is called for this group.
	 */
	rc = iopt_table_enforce_group_resv_regions(
		&hwpt->ioas->iopt, idev->group, &sw_msi_start);
	if (rc)
		return rc;
	rc = iommufd_device_setup_msi(idev, hwpt, sw_msi_start, flags);
	if (rc)
		goto out_iova;
	if (list_empty(&hwpt->devices)) {
		rc = iopt_table_add_domain(&hwpt->ioas->iopt, hwpt->domain);
		if (rc)
		goto out_iova;
	}
	return 0;
out_iova:
	iopt_remove_reserved_iova(&hwpt->ioas->iopt, idev->group);
	return rc;
}

static void device_detach_auto_hwpt(struct iommufd_device *idev,
				    struct iommufd_hw_pagetable *hwpt,
				    bool *destroy_auto_domain)
{
	if (list_empty(&hwpt->devices)) {
		iopt_table_remove_domain(&hwpt->ioas->iopt,
					 hwpt->domain);
		if (!list_empty(&hwpt->auto_domains_item)) {
			list_del_init(&hwpt->auto_domains_item);
			*destroy_auto_domain = true;
		}
	}
	iopt_remove_reserved_iova(&hwpt->ioas->iopt, idev->group);
}

static int iommufd_device_attach_domain(struct iommufd_device *idev,
					struct iommu_domain *domain,
				        ioasid_t pasid)
{
	int rc;

	if (pasid == INVALID_IOASID)
		rc = iommu_attach_group(domain, idev->group);
	else
		rc = iommu_attach_device_pasid(domain, idev->dev, pasid);
	return rc;
}

static void iommufd_device_detach_domain(struct iommufd_device *idev,
					 struct iommu_domain *domain,
					 ioasid_t pasid)
{
	if (pasid == INVALID_IOASID)
		iommu_detach_group(domain, idev->group);
	else
		iommu_detach_device_pasid(domain, idev->dev, pasid);

}

static int iommufd_device_attach_hwpt(struct iommufd_device *idev,
				      struct iommufd_hw_pagetable *hwpt,
				      struct iommufd_device_attach_data *attach)
{
	unsigned int flags = attach->flags;
	int rc;

	/*
	 * FIXME: Use a device-centric iommu api. For now check if the
	 * hw_pagetable already has a device of the same group joined to tell if
	 * we are the first and need to attach the group.
	 */
	if (iommufd_hw_pagetable_has_group(hwpt, idev->group))
		return 0;

	rc = iommufd_device_attach_domain(idev, hwpt->domain, attach->pasid);
	if (rc)
		return rc;

	rc = device_attach_auto_hwpt(idev, hwpt, flags);
	if (rc)
		iommu_detach_group(hwpt->domain, idev->group);

	return rc;
}

static void iommufd_device_detach_hwpt(struct iommufd_hwpt_device *hdev,
				       ioasid_t pasid,
				       bool *destroy_auto_domain)
{
	struct iommufd_device *idev = hdev->idev;
	struct iommufd_hw_pagetable *hwpt = hdev->hwpt;

	if (iommufd_hw_pagetable_has_group(hdev->hwpt, idev->group))
		return;

	device_detach_auto_hwpt(idev, hwpt, destroy_auto_domain);

	iommufd_device_detach_domain(idev, hwpt->domain, pasid);
}

static struct iommufd_hwpt_device *
iommufd_alloc_hwpt_device(struct iommufd_hw_pagetable *hwpt,
			  struct iommufd_device *idev, ioasid_t pasid)
{
	struct iommufd_hwpt_device *hdev;

	hdev = kzalloc(sizeof(*hdev), GFP_KERNEL);
	if (!hdev)
		return NULL;

	hdev->hwpt = hwpt;
	hdev->idev = idev;
	hdev->pasid = pasid;

	return hdev;
}

static int iommufd_device_do_attach(struct iommufd_device *idev,
				    struct iommufd_hw_pagetable *hwpt,
				    struct iommufd_device_attach_data *attach)
{
	struct iommufd_hwpt_device *hdev;
	int rc;

	mutex_lock(&hwpt->devices_lock);
	hdev = iommufd_alloc_hwpt_device(hwpt, idev, attach->pasid);
	if (!hdev) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	rc = iommufd_device_attach_hwpt(idev, hwpt, attach);
	if (rc)
		goto out_free;

	idev->hdev = hdev;
	refcount_inc(&hwpt->obj.users);
	list_add(&idev->devices_item, &hwpt->devices);
	mutex_unlock(&hwpt->devices_lock);
	return 0;
out_free:
	kfree(hdev);
out_unlock:
	mutex_unlock(&hwpt->devices_lock);
	return rc;
}

/*
 * When automatically managing the domains we search for a compatible domain in
 * the iopt and if one is found use it, otherwise create a new domain.
 * Automatic domain selection will never pick a manually created domain.
 */
static int iommufd_device_auto_get_domain(struct iommufd_device *idev,
					  struct iommufd_ioas *ioas,
					  struct iommufd_device_attach_data *attach)
{
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	/*
	 * There is no differentiation when domains are allocated, so any domain
	 * that is willing to attach to the device is interchangeable with any
	 * other.
	 */
	mutex_lock(&ioas->mutex);
	list_for_each_entry (hwpt, &ioas->auto_domains, auto_domains_item) {
		if (!refcount_inc_not_zero(&hwpt->obj.users))
			continue;

		/* FIXME: if the group is already attached to a domain make sure
		this returns EMEDIUMTYPE */
		rc = iommufd_device_do_attach(idev, hwpt, attach);
		refcount_dec(&hwpt->obj.users);
		if (rc) {
			if (rc == -EMEDIUMTYPE)
				continue;
			goto out_unlock;
		}
		goto out_unlock;
	}

	hwpt = iommufd_hw_pagetable_alloc(idev->ictx, ioas, idev->dev);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_unlock;
	}

	rc = iommufd_device_do_attach(idev, hwpt, attach);
	if (rc)
		goto out_abort;

	list_add_tail(&hwpt->auto_domains_item, &ioas->auto_domains);
	mutex_unlock(&ioas->mutex);
	iommufd_object_finalize(idev->ictx, &hwpt->obj);
	return 0;

out_abort:
	iommufd_object_abort_and_destroy(idev->ictx, &hwpt->obj);
out_unlock:
	mutex_unlock(&ioas->mutex);
	return rc;
}

static int __iommufd_device_attach(struct iommufd_device *idev, u32 *pt_id,
				   struct iommufd_device_attach_data *attach)
{
	struct iommufd_object *pt_obj;
	int rc;

	pt_obj = iommufd_get_object(idev->ictx, *pt_id, IOMMUFD_OBJ_ANY);
	if (IS_ERR(pt_obj))
		return PTR_ERR(pt_obj);

	switch (pt_obj->type) {
	case IOMMUFD_OBJ_HW_PAGETABLE: {
		struct iommufd_hw_pagetable *hwpt =
			container_of(pt_obj, struct iommufd_hw_pagetable, obj);

		rc = iommufd_device_do_attach(idev, hwpt, attach);
		if (rc)
			goto out_put_pt_obj;
		break;
	}
	case IOMMUFD_OBJ_IOAS: {
		struct iommufd_ioas *ioas =
			container_of(pt_obj, struct iommufd_ioas, obj);

		rc = iommufd_device_auto_get_domain(idev, ioas, attach);
		if (rc)
			goto out_put_pt_obj;
		break;
	}
	default:
		rc = -EINVAL;
		goto out_put_pt_obj;
	}

	refcount_inc(&idev->obj.users);
	*pt_id = idev->hdev->hwpt->obj.id;
	rc = 0;

out_put_pt_obj:
	iommufd_put_object(pt_obj);
	return rc;
}

/**
 * iommufd_device_attach - Connect a device to an iommu_domain
 * @idev: device to attach
 * @pt_id: Input a IOMMUFD_OBJ_IOAS, or IOMMUFD_OBJ_HW_PAGETABLE
 *         Output the IOMMUFD_OBJ_HW_PAGETABLE ID
 * @flags: Optional flags
 *
 * This connects the device to an iommu_domain, either automatically or manually
 * selected. Once this completes the device could do DMA.
 *
 * The caller should return the resulting pt_id back to userspace.
 * This function is undone by calling iommufd_device_detach().
 */
int iommufd_device_attach(struct iommufd_device *idev, u32 *pt_id,
			  unsigned int flags)
{
	struct iommufd_device_attach_data attach = { .flags = flags,
						     .pasid = INVALID_IOASID };

	return __iommufd_device_attach(idev, pt_id, &attach);
}
EXPORT_SYMBOL_GPL(iommufd_device_attach);

static void
__iommufd_device_pasid_detach(struct iommufd_device *idev, ioasid_t pasid)
{
	struct iommufd_hwpt_device *hdev = idev->hdev;
	struct iommufd_hw_pagetable *hwpt = hdev->hwpt;
	bool destroy_auto_domain = false;

	mutex_lock(&hwpt->ioas->mutex);
	mutex_lock(&hwpt->devices_lock);
	list_del(&idev->devices_item);
	iommufd_device_detach_hwpt(hdev, pasid, &destroy_auto_domain);
	kfree(hdev);
	mutex_unlock(&hwpt->devices_lock);
	mutex_unlock(&hwpt->ioas->mutex);

	if (destroy_auto_domain)
		iommufd_object_destroy_user(idev->ictx, &hwpt->obj);
	else
		refcount_dec(&hwpt->obj.users);

	idev->hdev = NULL;

	refcount_dec(&idev->obj.users);
}

void iommufd_device_detach(struct iommufd_device *idev)
{
	__iommufd_device_pasid_detach(idev, INVALID_IOASID);
}
EXPORT_SYMBOL_GPL(iommufd_device_detach);

/**
 * iommufd_device_pasid_attach - Connect a device+pasid to an iommu_domain
 * @idev: device to attach
 * @pasid: pasid to attach
 * @pt_id: Input a IOMMUFD_OBJ_IOAS, or IOMMUFD_OBJ_HW_PAGETABLE
 *         Output the IOMMUFD_OBJ_HW_PAGETABLE ID
 * @flags: Optional flags
 *
 * This connects the device to an iommu_domain, either automatically or manually
 * selected. Once this completes the device could do DMA.
 *
 * The caller should return the resulting pt_id back to userspace.
 * This function is undone by calling iommufd_device_pasid_detach().
 */
int iommufd_device_pasid_attach(struct iommufd_device *idev, u32 *pt_id,
				ioasid_t pasid, unsigned int flags)
{
	struct iommufd_device_attach_data attach = { .flags = flags, .pasid = pasid };

	return __iommufd_device_attach(idev, pt_id, &attach);
}
EXPORT_SYMBOL_GPL(iommufd_device_pasid_attach);

void iommufd_device_pasid_detach(struct iommufd_device *idev,
				 ioasid_t pasid)
{
	__iommufd_device_pasid_detach(idev, pasid);
}
EXPORT_SYMBOL_GPL(iommufd_device_pasid_detach);

#ifdef CONFIG_IOMMUFD_TEST
/*
 * Creating a real iommufd_device is too hard, bypass creating a iommufd_device
 * and go directly to attaching a domain.
 */
struct iommufd_hw_pagetable *
iommufd_device_selftest_attach(struct iommufd_ctx *ictx,
			       struct iommufd_ioas *ioas,
			       struct device *mock_dev)
{
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	hwpt = iommufd_hw_pagetable_alloc(ictx, ioas, mock_dev);
	if (IS_ERR(hwpt))
		return hwpt;

	rc = iopt_table_add_domain(&hwpt->ioas->iopt, hwpt->domain);
	if (rc)
		goto out_hwpt;

	refcount_inc(&hwpt->obj.users);
	iommufd_object_finalize(ictx, &hwpt->obj);
	return hwpt;

out_hwpt:
	iommufd_object_abort_and_destroy(ictx, &hwpt->obj);
	return ERR_PTR(rc);
}

void iommufd_device_selftest_detach(struct iommufd_ctx *ictx,
				    struct iommufd_hw_pagetable *hwpt)
{
	iopt_table_remove_domain(&hwpt->ioas->iopt, hwpt->domain);
	refcount_dec(&hwpt->obj.users);
}
#endif
