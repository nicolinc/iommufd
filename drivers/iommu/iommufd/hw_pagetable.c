// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommu.h>

#include "iommufd_private.h"

void iommufd_hw_pagetable_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);

	if (!list_empty(&hwpt->hwpt_item)) {
		mutex_lock(&hwpt->ioas->mutex);
		list_del(&hwpt->hwpt_item);
		mutex_unlock(&hwpt->ioas->mutex);

		iopt_table_remove_domain(&hwpt->ioas->iopt, hwpt->domain);
	}

	if (hwpt->domain)
		iommu_domain_free(hwpt->domain);

	refcount_dec(&hwpt->ioas->obj.users);
}

int iommufd_hw_pagetable_enforce_cc(struct iommufd_hw_pagetable *hwpt)
{
	if (hwpt->enforce_cache_coherency)
		return 0;

	if (hwpt->domain->ops->enforce_cache_coherency)
		hwpt->enforce_cache_coherency =
			hwpt->domain->ops->enforce_cache_coherency(
				hwpt->domain);
	if (!hwpt->enforce_cache_coherency)
		return -EINVAL;
	return 0;
}

/**
 * iommufd_hw_pagetable_alloc() - Get an iommu_domain for a device
 * @ictx: iommufd context
 * @ioas: IOAS to associate the domain with
 * @idev: Device to get an iommu_domain for
 * @immediate_attach: True if idev should be attached to the hwpt
 *
 * Allocate a new iommu_domain and return it as a hw_pagetable. The HWPT
 * will be linked to the given ioas and upon return the underlying iommu_domain
 * is fully popoulated.
 */
struct iommufd_hw_pagetable *
iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct iommufd_ioas *ioas,
			   struct iommufd_device *idev, bool immediate_attach)
{
	const struct iommu_ops *ops = dev_iommu_ops(idev->dev);
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	lockdep_assert_held(&ioas->mutex);

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	INIT_LIST_HEAD(&hwpt->hwpt_item);
	/* Pairs with iommufd_hw_pagetable_destroy() */
	refcount_inc(&ioas->obj.users);
	hwpt->ioas = ioas;

	if (ops->domain_alloc_user)
		hwpt->domain = ops->domain_alloc_user(idev->dev, NULL, NULL);
	else
		hwpt->domain = iommu_domain_alloc(idev->dev->bus);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	/*
	 * Set the coherency mode before we do iopt_table_add_domain() as some
	 * iommus have a per-PTE bit that controls it and need to decide before
	 * doing any maps. It is an iommu driver bug to report
	 * IOMMU_CAP_ENFORCE_CACHE_COHERENCY but fail enforce_cache_coherency on
	 * a new domain.
	 */
	if (idev->enforce_cache_coherency) {
		rc = iommufd_hw_pagetable_enforce_cc(hwpt);
		if (WARN_ON(rc))
			goto out_abort;
	}

	mutex_lock(&idev->igroup->lock);

	/*
	 * immediate_attach exists only to accommodate iommu drivers that cannot
	 * directly allocate a domain. These drivers do not finish creating the
	 * domain until attach is completed. Thus we must have this call
	 * sequence. Once those drivers are fixed this should be removed.
	 *
	 * Note we hold the igroup->lock here which prevents any other thread
	 * from observing igroup->hwpt until we finish setting it up.
	 */
	if (immediate_attach) {
		rc = iommufd_hw_pagetable_attach(hwpt, idev);
		if (rc)
			goto out_unlock;
	}

	rc = iopt_table_add_domain(&hwpt->ioas->iopt, hwpt->domain);
	if (rc)
		goto out_detach;

	/* ioas->hwpt_list is hwpts after iopt_table_add_domain() */
	list_add_tail(&hwpt->hwpt_item, &hwpt->ioas->hwpt_list);

	mutex_unlock(&idev->igroup->lock);
	return hwpt;

out_detach:
	if (immediate_attach)
		iommufd_hw_pagetable_detach(idev);
out_unlock:
	mutex_unlock(&idev->igroup->lock);
out_abort:
	iommufd_object_abort_and_destroy(ictx, &hwpt->obj);
	return ERR_PTR(rc);
}

/*
 * size of page table type specific data, indexed by
 * enum iommu_pgtbl_data_type.
 */
static const size_t iommufd_hwpt_info_size[] = {
	[IOMMU_PGTBL_DATA_NONE] = 0,
};

int iommufd_hwpt_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommufd_hw_pagetable *hwpt;
	struct iommu_hwpt_alloc *cmd = ucmd->cmd;
	struct iommufd_ctx *ictx = ucmd->ictx;
	struct iommufd_object *pt_obj = NULL;
	struct iommufd_ioas *ioas = NULL;
	struct iommufd_object *dev_obj;
	struct iommufd_device *idev;
	const struct iommu_ops *ops;
	void *data = NULL;
	u32 driver_type, klen;
	int rc;

	if (cmd->__reserved || cmd->flags)
		return -EOPNOTSUPP;

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);

	ops = dev_iommu_ops(idev->dev);
	if (!ops) {
		rc = -EOPNOTSUPP;
		goto out_put_dev;
	}

	driver_type = ops->driver_type;

	/* data_type should be a supported type by the hardware */
	if (!((1 << cmd->data_type) &
			iommufd_supported_pgtbl_types[driver_type])) {
		rc = -EINVAL;
		goto out_put_dev;
	}

	pt_obj = iommufd_get_object(ictx, cmd->pt_id, IOMMUFD_OBJ_ANY);
	if (IS_ERR(pt_obj)) {
		rc = -EINVAL;
		goto out_put_dev;
	}

	switch (pt_obj->type) {
	case IOMMUFD_OBJ_IOAS:
		ioas = container_of(pt_obj, struct iommufd_ioas, obj);
		break;
	default:
		rc = -EINVAL;
		goto out_put_pt;
	}

	klen = iommufd_hwpt_info_size[cmd->data_type];
	if (klen) {
		if (!cmd->data_len) {
			rc = -EINVAL;
			goto out_put_pt;
		}

		data = kzalloc(klen, GFP_KERNEL);
		if (!data) {
			rc = -ENOMEM;
			goto out_put_pt;
		}

		rc = copy_struct_from_user(data, klen,
					   u64_to_user_ptr(cmd->data_uptr),
					   cmd->data_len);
		if (rc)
			goto out_free_data;
	}

	mutex_lock(&ioas->mutex);
	hwpt = iommufd_hw_pagetable_alloc(ucmd->ictx, ioas, idev, false);
	mutex_unlock(&ioas->mutex);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_free_data;
	}

	cmd->out_hwpt_id = hwpt->obj.id;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_destroy_hwpt;

	kfree(data);
	iommufd_put_object(pt_obj);
	iommufd_put_object(dev_obj);
	return 0;
out_destroy_hwpt:
	iommufd_object_abort_and_destroy(ucmd->ictx, &hwpt->obj);
out_free_data:
	kfree(data);
out_put_pt:
	iommufd_put_object(pt_obj);
out_put_dev:
	iommufd_put_object(dev_obj);
	return rc;
}
