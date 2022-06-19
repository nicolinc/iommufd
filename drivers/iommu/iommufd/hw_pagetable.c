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

	WARN_ON(!list_empty(&hwpt->devices));

	iommu_domain_free(hwpt->domain);
	if (hwpt->parent)
		refcount_dec(&hwpt->parent->obj.users);
	if (hwpt->ioas)
		refcount_dec(&hwpt->ioas->obj.users);
	if (hwpt->user_data)
		kfree(hwpt->user_data);
	mutex_destroy(&hwpt->devices_lock);
}

static struct iommufd_hw_pagetable *
__iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct device *dev,
			     void *parent, enum iommufd_object_type parent_type,
			     void *user_data, unsigned domain_type)
{
	struct iommu_domain *parent_domain = NULL;
	struct iommufd_object *parent_obj;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	switch (parent_type) {
	case IOMMUFD_OBJ_HW_PAGETABLE:
		hwpt->parent = (struct iommufd_hw_pagetable *)parent;
		parent_domain = hwpt->parent->domain;
		parent_obj = &hwpt->parent->obj;
		break;
	case IOMMUFD_OBJ_IOAS:
		hwpt->ioas = (struct iommufd_ioas *)parent;
		parent_obj = &hwpt->ioas->obj;
		break;
	default:
		rc = -EINVAL;
		goto out_abort;
	}

	hwpt->domain = iommu_domain_alloc_user(dev, parent_domain,
					       user_data, domain_type);
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
	mutex_init(&hwpt->devices_lock);
	/* Pairs with iommufd_hw_pagetable_destroy() */
	refcount_inc(&parent_obj->users);
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
	return __iommufd_hw_pagetable_alloc(ictx, dev,
					    (void *)ioas, IOMMUFD_OBJ_IOAS,
					    NULL, IOMMU_DOMAIN_UNMANAGED);
}

static const size_t iommufd_hwpt_data_len[] = {
	[IOMMU_HWPT_DATA_NONE] = 0,
	[IOMMU_HWPT_DATA_INTEL_VTD] = sizeof(struct iommu_hwpt_intel_vtd),
	[IOMMU_HWPT_DATA_ARM_SMMUV3] = sizeof(struct iommu_hwpt_arm_smmuv3),
};

int iommufd_hwpt_alloc(struct iommufd_ucmd *ucmd)
{
	enum iommufd_object_type parent_type = IOMMUFD_OBJ_IOAS;
	unsigned domain_type = IOMMU_DOMAIN_UNMANAGED;
	struct iommu_hwpt_alloc *cmd = ucmd->cmd;
	struct iommufd_object *parent_obj = NULL;
	struct iommufd_ctx *ictx = ucmd->ictx;
	struct iommufd_hw_pagetable *hwpt;
	struct device *dev;
	void *data = NULL;
	void *parent;
	int rc;

	if (cmd->__reserved)
		return -EOPNOTSUPP;

	dev = iommufd_find_dev_by_id(ictx, cmd->dev_id);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	if (cmd->data_len && cmd->data_type != IOMMU_HWPT_DATA_NONE) {
		if (iommufd_hwpt_data_len[cmd->data_type] != cmd->data_len)
			return -EINVAL;

		data = kzalloc(cmd->data_len, GFP_KERNEL);
		if (!data)
			return -ENOMEM;

		rc = copy_struct_from_user(data, cmd->data_len,
					   (void __user *)cmd->data_uptr,
					   cmd->data_len);
		if (rc)
			goto out_free_data;
	}

	if (cmd->flags & IOMMU_HWPT_FLAG_NESTING) {
		parent_type = IOMMUFD_OBJ_HW_PAGETABLE;
		domain_type = IOMMU_DOMAIN_NESTING;
	}

	parent_obj = iommufd_get_object(ictx, cmd->parent_id, parent_type);
	if (IS_ERR(parent_obj)) {
		rc = -EINVAL;
		goto out_free_data;
	}
	if (cmd->flags & IOMMU_HWPT_FLAG_NESTING)
		parent = container_of(parent_obj,
				      struct iommufd_hw_pagetable, obj);
	else
		parent = container_of(parent_obj, struct iommufd_ioas, obj);

	hwpt = __iommufd_hw_pagetable_alloc(ictx, dev, parent, parent_type,
					    data, domain_type);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_put_parent;
	}

	hwpt->user_data = data;
	cmd->out_hwpt_id = hwpt->obj.id;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_destroy_hwpt;

	iommufd_object_finalize(ucmd->ictx, &hwpt->obj);
	iommufd_put_object(parent_obj);
	return 0;
out_destroy_hwpt:
	iommufd_object_abort_and_destroy(ucmd->ictx, &hwpt->obj);
out_put_parent:
	if (parent_obj)
		iommufd_put_object(parent_obj);
out_free_data:
	if (data)
		kfree(data);
	return rc;
}

int iommufd_hwpt_invalidate_cache(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_invalidate_s1_cache *cmd = ucmd->cmd;
	struct iommufd_object *obj;
	struct iommufd_hw_pagetable *hwpt;
	int rc = 0;

	if (cmd->flags)
		return -EOPNOTSUPP;

	/* TODO: more sanity check when the struct is finalized */
	obj = iommufd_get_object(ucmd->ictx, cmd->hwpt_id,
				 IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	hwpt = container_of(obj, struct iommufd_hw_pagetable, obj);

	/* Only support nested stage-1 that must have a parent hwpt */
	if (!hwpt->parent) {
		rc = -EINVAL;
		goto out_put_hwpt;
	}

	iommu_domain_cache_inv(hwpt->domain, &cmd->info);
out_put_hwpt:
	iommufd_put_object(obj);
	return rc;
}
