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
	bool finalize_done;

	WARN_ON(!list_empty(&hwpt->devices));

	if (!hwpt->parent) {
		mutex_lock(&hwpt->ioas->mutex);
		finalize_done = !list_empty(&hwpt->hwpt_item);
		list_del(&hwpt->hwpt_item);
		mutex_unlock(&hwpt->ioas->mutex);

		if (finalize_done)
			iopt_table_remove_domain(&hwpt->ioas->iopt, hwpt->domain);
	} else {
		refcount_dec(&hwpt->parent->obj.users);
	}
	iommu_domain_free(hwpt->domain);
	refcount_dec(&hwpt->ioas->obj.users);
	mutex_destroy(&hwpt->devices_lock);
}

static struct iommufd_hw_pagetable *
__iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx,
			     struct iommufd_ioas *ioas,
			     struct device *dev,
			     struct iommufd_hw_pagetable *parent,
			     void *user_data)
{
	const struct iommu_ops *ops;
	struct iommu_domain *parent_domain = NULL;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	if (WARN_ON(!ioas && !parent))
		return ERR_PTR(-EINVAL);

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	ops = dev_iommu_ops(dev);
	if (!ops || !ops->domain_alloc_user) {
		rc = -EOPNOTSUPP;
		goto out_abort;
	}

	if (parent)
		parent_domain = parent->domain;

	hwpt->domain = ops->domain_alloc_user(dev, parent_domain, user_data);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	hwpt->parent = parent;
	INIT_LIST_HEAD(&hwpt->devices);
	INIT_LIST_HEAD(&hwpt->hwpt_item);
	mutex_init(&hwpt->devices_lock);
	if (parent)
		refcount_inc(&parent->obj.users);

	/* Pairs with iommufd_hw_pagetable_destroy() */
	refcount_inc(&ioas->obj.users);
	hwpt->ioas = ioas;
	return hwpt;

out_abort:
	iommufd_object_abort(ictx, &hwpt->obj);
	return ERR_PTR(rc);
}

void iommufd_hw_pagetable_finalize(struct iommufd_ctx *ictx,
				   struct iommufd_hw_pagetable *hwpt)
{
	lockdep_assert_held(&hwpt->ioas->mutex);

	/*
	 * Once the hwpt is on this list it can become attached through the
	 * auto_domains mechanism so this must be called after
	 * iopt_table_add_domain().
	 */
	list_add_tail(&hwpt->hwpt_item, &hwpt->ioas->hwpt_list);
	iommufd_object_finalize(ictx, &hwpt->obj);
}

/**
 * iommufd_hw_pagetable_alloc() - Get an iommu_domain for a device
 * @ictx: iommufd context
 * @ioas: IOAS to associate the domain with
 * @dev: Device to get an iommu_domain for
 *
 * Allocate a new iommu_domain and return it as a hw_pagetable.
 * iommufd_hw_pagetable_finalize() must be called to successfully complete the
 * allocation, otherwise iommufd_object_abort_and_destroy() should be called.
 */
struct iommufd_hw_pagetable *
iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct iommufd_ioas *ioas,
			   struct device *dev)
{
	return __iommufd_hw_pagetable_alloc(ictx, ioas, dev, NULL, NULL);
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
	struct device *dev;
	const struct iommu_ops *ops;
	void *data = NULL;
	u32 driver_type, klen;
	int rc;

	if (cmd->__reserved || cmd->flags)
		return -EOPNOTSUPP;

	dev_obj = iommufd_get_object(ucmd->ictx, cmd->dev_id,
				     IOMMUFD_OBJ_ANY);
	if (IS_ERR(dev_obj))
		return PTR_ERR(dev_obj);

	dev = iommufd_obj_dev(dev_obj);
	if (!dev) {
		rc = -EINVAL;
		goto out_put_dev;
	}

	ops = dev_iommu_ops(dev);
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

	hwpt = __iommufd_hw_pagetable_alloc(ictx, ioas, dev, NULL, data);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_free_data;
	}

	rc = iopt_table_add_domain(&hwpt->ioas->iopt, hwpt->domain);
	if (rc)
		goto out_destroy_hwpt;

	cmd->out_hwpt_id = hwpt->obj.id;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_destroy_hwpt;

	kfree(data);
	mutex_lock(&ioas->mutex);
	iommufd_hw_pagetable_finalize(ictx, hwpt);
	mutex_unlock(&ioas->mutex);
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
