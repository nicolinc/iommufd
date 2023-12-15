// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */

#include <linux/iommufd.h>

#include "iommufd_private.h"

#define viommu_struct_alloc(name)                                              \
	struct iommufd_##name *_iommufd_##name##_alloc(size_t size)            \
	{                                                                      \
		struct iommufd_object *obj;                                    \
		if (WARN_ON(size < sizeof(struct iommufd_##name)))             \
			return NULL;                                           \
		obj = ___iommufd_object_alloc(size);                           \
		if (IS_ERR(obj))                                               \
			return NULL;                                           \
		return container_of(obj, struct iommufd_##name, obj);          \
	}

viommu_struct_alloc(viommu);

void iommufd_viommu_destroy(struct iommufd_object *obj)
{
	struct iommufd_viommu *viommu =
		container_of(obj, struct iommufd_viommu, obj);

	if (viommu->ops && viommu->ops->free)
		viommu->ops->free(viommu);
	refcount_dec(&viommu->hwpt->common.obj.users);
}

int iommufd_viommu_alloc_ioctl(struct iommufd_ucmd *ucmd)
{
	struct iommu_viommu_alloc *cmd = ucmd->cmd;
	struct iommufd_hwpt_paging *hwpt_paging;
	struct iommu_device *iommu_dev;
	struct iommufd_viommu *viommu;
	struct iommufd_device *idev;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);
	iommu_dev = idev->dev->iommu->iommu_dev;

	if (!iommu_dev->ops->viommu_alloc) {
		rc = -EOPNOTSUPP;
		goto out_put_idev;
	}

	hwpt_paging = iommufd_get_hwpt_paging(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt_paging)) {
		rc = PTR_ERR(hwpt_paging);
		goto out_put_idev;
	}

	if (!hwpt_paging->nest_parent) {
		rc = -EINVAL;
		goto out_put_hwpt;
	}

	viommu = iommu_dev->ops->viommu_alloc(idev->dev, cmd->type,
					      hwpt_paging->common.domain);
	if (IS_ERR(viommu)) {
		rc = PTR_ERR(viommu);
		goto out_put_hwpt;
	}

	/* iommufd_object_finalize will store the viommu->obj.id */
	rc = xa_alloc(&ucmd->ictx->objects, &viommu->obj.id, XA_ZERO_ENTRY,
		      xa_limit_31b, GFP_KERNEL_ACCOUNT);
	if (rc)
		goto out_free;

	viommu->obj.type = IOMMUFD_OBJ_VIOMMU;
	viommu->type = cmd->type;

	viommu->ictx = ucmd->ictx;
	viommu->hwpt = hwpt_paging;
	viommu->iommu_dev = idev->dev->iommu->iommu_dev;
	cmd->out_viommu_id = viommu->obj.id;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_erase_xa;
	iommufd_object_finalize(ucmd->ictx, &viommu->obj);
	refcount_inc(&viommu->hwpt->common.obj.users);
	goto out_put_hwpt;

out_erase_xa:
	xa_erase(&ucmd->ictx->objects, viommu->obj.id);
out_free:
	if (viommu->ops && viommu->ops->free)
		viommu->ops->free(viommu);
	kfree(viommu);
out_put_hwpt:
	iommufd_put_object(ucmd->ictx, &hwpt_paging->common.obj);
out_put_idev:
	iommufd_put_object(ucmd->ictx, &idev->obj);
	return rc;
}
