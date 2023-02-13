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

	mutex_lock(&hwpt->ioas->mutex);
	finalize_done = !list_empty(&hwpt->hwpt_item);
	list_del(&hwpt->hwpt_item);
	mutex_unlock(&hwpt->ioas->mutex);

	if (finalize_done)
		iopt_table_remove_domain(&hwpt->ioas->iopt, hwpt->domain);

	iommu_domain_free(hwpt->domain);
	refcount_dec(&hwpt->ioas->obj.users);
	mutex_destroy(&hwpt->devices_lock);
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

	INIT_LIST_HEAD(&hwpt->devices);
	INIT_LIST_HEAD(&hwpt->hwpt_item);
	mutex_init(&hwpt->devices_lock);
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
