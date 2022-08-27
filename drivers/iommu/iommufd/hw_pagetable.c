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
			     struct iommufd_hw_pagetable *parent_hwpt,
			     struct iommufd_ioas *parent_ioas,
			     void *user_data, unsigned domain_type)
{
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	hwpt->domain = iommu_domain_alloc_user(dev, parent_hwpt->domain,
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
	if (parent_ioas) {
		/* Pairs with iommufd_hw_pagetable_destroy() */
		refcount_inc(&parent_ioas->obj.users);
		hwpt->ioas = parent_ioas;
	}
	if (parent_hwpt) {
		/* Pairs with iommufd_hw_pagetable_destroy() */
		refcount_inc(&parent_hwpt->obj.users);
		hwpt->parent = parent_hwpt;
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
	return __iommufd_hw_pagetable_alloc(ictx, dev, NULL, ioas, NULL,
					    IOMMU_DOMAIN_UNMANAGED);
}

static const size_t iommufd_hwpt_data_len[] = {
	[IOMMU_HWPT_DATA_NONE] = 0,
	[IOMMU_HWPT_DATA_INTEL_VTD] = sizeof(struct iommu_hwpt_intel_vtd),
};

int iommufd_hwpt_alloc(struct iommufd_ucmd *ucmd)
{
	unsigned domain_type = IOMMU_DOMAIN_UNMANAGED;
	struct iommufd_hw_pagetable *hwpt, *parent;
	struct iommu_hwpt_alloc *cmd = ucmd->cmd;
	struct iommufd_object *parent_obj = NULL;
	struct iommufd_ctx *ictx = ucmd->ictx;
	struct iommufd_ioas *ioas;
	struct device *dev;
	void *data = NULL;
	int rc;

	if (cmd->reserved || cmd->hwpt_type > IOMMU_HWPT_TYPE_S1)
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

	switch (cmd->hwpt_type) {
	case IOMMU_HWPT_TYPE_S2:
		parent_obj = iommufd_get_object(ictx, cmd->parent_id,
						IOMMUFD_OBJ_IOAS);
		if (IS_ERR(parent_obj)) {
			rc = -EINVAL;
			goto out_free_data;
		}
		ioas = container_of(parent_obj, struct iommufd_ioas, obj);
		hwpt = __iommufd_hw_pagetable_alloc(ictx, dev, NULL, ioas,
						    data, domain_type);
		if (rc)
			goto out_destroy_hwpt;
		break;
	case IOMMU_HWPT_TYPE_S1:
		if (cmd->flags & IOMMU_HWPT_FLAG_NESTING) {
			parent_obj = iommufd_get_object(ictx, cmd->parent_id,
					IOMMUFD_OBJ_HW_PAGETABLE);
			if (IS_ERR(parent_obj)) {
				rc = -EINVAL;
				goto out_free_data;
			}
			parent = container_of(parent_obj,
					      struct iommufd_hw_pagetable, obj);
			domain_type = IOMMU_DOMAIN_NESTING;
		}
		hwpt = __iommufd_hw_pagetable_alloc(ictx, dev, parent, NULL,
						    data, domain_type);
		break;
	default:
		rc = -EINVAL;
		goto out_free_data;
	}

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
