// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>

#include "iommufd_private.h"

void iommufd_hw_pagetable_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);

	WARN_ON(!list_empty(&hwpt->devices));

	kfree(hwpt->user_data);
	iommu_domain_free(hwpt->domain);
	if (hwpt->parent)
		refcount_dec(&hwpt->parent->obj.users);
	if (hwpt->ioas) {
		WARN_ON(!refcount_dec_if_one(&hwpt->devices_users));
		refcount_dec(&hwpt->ioas->obj.users);
	}
	mutex_destroy(&hwpt->devices_lock);
}

static struct iommufd_hw_pagetable *
__iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct device *dev,
			     struct iommufd_ioas *ioas,
			     struct iommufd_hw_pagetable *parent,
			     void *user_data, size_t data_len)
{
	struct iommu_domain *parent_domain = NULL;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	if (parent)
		parent_domain = parent->domain;

	hwpt->domain = iommu_domain_alloc_user(dev, parent_domain,
					       user_data, data_len);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	/*
	 * If the IOMMU can block non-coherent operations (ie PCIe TLPs with
	 * no-snoop set) then always turn it on. We currently don't have a uAPI
	 * to allow userspace to restore coherency if it wants to use no-snoop
	 * TLPs.
	 */
	if (hwpt->domain->ops->enforce_cache_coherency)
		hwpt->enforce_cache_coherency =
			hwpt->domain->ops->enforce_cache_coherency(
				hwpt->domain);

	INIT_LIST_HEAD(&hwpt->devices);
	INIT_LIST_HEAD(&hwpt->hwpt_item);
	if (parent) {
		/* Pairs with iommufd_hw_pagetable_destroy() */
		refcount_inc(&parent->obj.users);
		hwpt->parent = parent;
	}
	if (ioas) {
		/* The below two fields are dummy for nested hwpt */
		mutex_init(&hwpt->devices_lock);
		refcount_set(&hwpt->devices_users, 1);

		/* Pairs with iommufd_hw_pagetable_destroy() */
		refcount_inc(&ioas->obj.users);
		hwpt->ioas = ioas;
	}
	return hwpt;

out_abort:
	iommufd_object_abort(ictx, &hwpt->obj);
	return ERR_PTR(rc);
}

/**
 * iommufd_hw_pagetable_alloc() - Get an iommu_domain for a device
 * @ictx: iommufd context
 * @ioas: IOAS to associate the domain with
 * @dev: Device to get an iommu_domain for
 *
 * Allocate a new iommu_domain and return it as a hw_pagetable.
 */
struct iommufd_hw_pagetable *
iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct iommufd_ioas *ioas,
			   struct device *dev)
{
	return __iommufd_hw_pagetable_alloc(ictx, dev, ioas, NULL, NULL, 0);
}

int iommufd_hwpt_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommufd_hw_pagetable *hwpt, *parent = NULL;
	struct iommu_hwpt_alloc *cmd = ucmd->cmd;
	struct iommufd_ctx *ictx = ucmd->ictx;
	struct iommufd_object *pt_obj = NULL;
	struct iommufd_ioas *ioas = NULL;
	struct device *dev;
	void *data = NULL;
	int rc;

	if (cmd->__reserved || cmd->flags)
		return -EOPNOTSUPP;

	dev = iommufd_find_dev_by_id(ictx, cmd->dev_id);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	pt_obj = iommufd_get_object(ictx, cmd->pt_id, IOMMUFD_OBJ_ANY);
	if (IS_ERR(pt_obj))
		return -EINVAL;

	switch (pt_obj->type) {
	case IOMMUFD_OBJ_HW_PAGETABLE:
		parent = container_of(pt_obj, struct iommufd_hw_pagetable, obj);
		if (parent->auto_domain) {
			rc = -EINVAL;
			goto out_put_pt;
		}
		break;
	case IOMMUFD_OBJ_IOAS:
		ioas = container_of(pt_obj, struct iommufd_ioas, obj);
		break;
	default:
		rc = -EINVAL;
		goto out_put_pt;
	}

	if (cmd->data_len && cmd->data_type != IOMMU_DEVICE_DATA_NONE) {
		data = kzalloc(cmd->data_len, GFP_KERNEL);
		if (!data) {
			rc = -ENOMEM;
			goto out_put_pt;
		}

		rc = copy_struct_from_user(data, cmd->data_len,
					   (void __user *)cmd->data_uptr,
					   cmd->data_len);
		if (rc)
			goto out_free_data;
	}

	if (ioas)
		mutex_lock(&ioas->mutex);
	hwpt = __iommufd_hw_pagetable_alloc(ictx, dev, ioas, parent,
					    data, cmd->data_len);
	if (ioas)
		mutex_unlock(&ioas->mutex);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_free_data;
	}

	hwpt->user_data = data;
	cmd->out_hwpt_id = hwpt->obj.id;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_destroy_hwpt;

	iommufd_object_finalize(ucmd->ictx, &hwpt->obj);
	iommufd_put_object(pt_obj);
	return 0;
out_destroy_hwpt:
	iommufd_object_abort_and_destroy(ucmd->ictx, &hwpt->obj);
out_free_data:
	kfree(data);
out_put_pt:
	iommufd_put_object(pt_obj);
	return rc;
}
