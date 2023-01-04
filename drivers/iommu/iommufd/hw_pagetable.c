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

	iommu_domain_free(hwpt->domain);
	refcount_dec(&hwpt->ioas->obj.users);
	if (hwpt->parent) {
		refcount_dec(&hwpt->parent->obj.users);
	} else {
		WARN_ON(!refcount_dec_if_one(hwpt->devices_users));
		mutex_destroy(hwpt->devices_lock);
		kfree(hwpt->devices_lock);
	}
}

static struct iommufd_hw_pagetable *
__iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct device *dev,
			     struct iommufd_ioas *ioas, u32 data_type,
			     struct iommufd_hw_pagetable *parent,
			     void *user_data, size_t data_len)
{
	struct iommu_domain *parent_domain = NULL;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	if (WARN_ON(!ioas && !parent))
		return ERR_PTR(-EINVAL);

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	if (parent)
		parent_domain = parent->domain;

	hwpt->domain = iommu_domain_alloc_user(dev, data_type, parent_domain,
					       user_data, data_len);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	INIT_LIST_HEAD(&hwpt->devices);
	INIT_LIST_HEAD(&hwpt->hwpt_item);
	hwpt->parent = parent;
	if (parent) {
		/* Always reuse parent's devices_lock and devices_users... */
		hwpt->devices_lock = parent->devices_lock;
		hwpt->devices_users = parent->devices_users;
		refcount_inc(&parent->obj.users);
	} else {
		/* ...otherwise, allocate a new pair */
		hwpt->devices_lock = kzalloc(sizeof(*hwpt->devices_lock) +
					     sizeof(*hwpt->devices_users),
					     GFP_KERNEL);
		if (!hwpt->devices_lock) {
			rc = -ENOMEM;
			goto out_free_domain;
		}
		mutex_init(hwpt->devices_lock);
		hwpt->devices_users = (refcount_t *)&hwpt->devices_lock[1];
		refcount_set(hwpt->devices_users, 1);
	}

	/* Pairs with iommufd_hw_pagetable_destroy() */
	refcount_inc(&ioas->obj.users);
	hwpt->ioas = ioas;
	return hwpt;

out_free_domain:
	iommu_domain_free(hwpt->domain);
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
	return __iommufd_hw_pagetable_alloc(ictx, dev, ioas,
					    IOMMU_DEVICE_DATA_NONE,
					    NULL, NULL, 0);
}
