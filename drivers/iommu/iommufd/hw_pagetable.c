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

	iommu_domain_free(hwpt->domain);
	refcount_dec(&hwpt->ioas->obj.users);
	WARN_ON(!refcount_dec_if_one(hwpt->devices_users));
	kfree(hwpt->devices_users);
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
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	hwpt->domain = iommu_domain_alloc(dev->bus);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	INIT_LIST_HEAD(&hwpt->hwpt_item);
	hwpt->devices_users = kzalloc(sizeof(*hwpt->devices_users), GFP_KERNEL);
	if (!hwpt->devices_users) {
		rc = -ENOMEM;
		goto out_free_domain;
	}
	refcount_set(hwpt->devices_users, 1);

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
