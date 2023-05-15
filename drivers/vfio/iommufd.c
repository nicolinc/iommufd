// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/vfio.h>
#include <linux/iommufd.h>

#include "vfio.h"

MODULE_IMPORT_NS(IOMMUFD);
MODULE_IMPORT_NS(IOMMUFD_VFIO);

static void vfio_noiommu_access_unmap(void *data, unsigned long iova,
				      unsigned long length)
{
}

static const struct iommufd_access_ops vfio_user_noiommu_ops = {
	.needs_pin_pages = 1,
	.unmap = vfio_noiommu_access_unmap,
};

static int vfio_iommufd_noiommu_bind(struct vfio_device *vdev,
				     struct iommufd_ctx *ictx,
				     u32 *out_device_id)
{
	struct iommufd_access *user;

	lockdep_assert_held(&vdev->dev_set->lock);

	user = iommufd_access_create(ictx, &vfio_user_noiommu_ops,
				     vdev, out_device_id);
	if (IS_ERR(user))
		return PTR_ERR(user);
	vdev->noiommu_access = user;
	return 0;
}

static void vfio_iommufd_noiommu_unbind(struct vfio_device *vdev)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->noiommu_access) {
		iommufd_access_destroy(vdev->noiommu_access);
		vdev->noiommu_access = NULL;
	}
}

int vfio_iommufd_compat_probe_noiommu(struct vfio_device *device,
				      struct iommufd_ctx *ictx)
{
	u32 ioas_id;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	/*
	 * Require no compat ioas to be assigned to proceed.  The basic
	 * statement is that the user cannot have done something that
	 * implies they expected translation to exist
	 */
	if (!iommufd_vfio_compat_ioas_get_id(ictx, &ioas_id))
		return -EPERM;
	return 0;
}

int vfio_iommufd_bind(struct vfio_device_file *df)
{
	struct vfio_device *vdev = df->device;
	struct iommufd_ctx *ictx = df->iommufd;

	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->noiommu)
		return vfio_iommufd_noiommu_bind(vdev, ictx, &df->devid);

	return vdev->ops->bind_iommufd(vdev, ictx, &df->devid);
}

int vfio_iommufd_compat_attach_ioas(struct vfio_device *vdev,
				    struct iommufd_ctx *ictx)
{
	u32 ioas_id;
	int ret;

	lockdep_assert_held(&vdev->dev_set->lock);

	/* compat noiommu does not need to do ioas attach */
	if (vdev->noiommu)
		return 0;

	ret = iommufd_vfio_compat_ioas_get_id(ictx, &ioas_id);
	if (ret)
		return ret;

	/* The legacy path has no way to return the selected pt_id */
	return vdev->ops->attach_ioas(vdev, &ioas_id);
}

void vfio_iommufd_unbind(struct vfio_device_file *df)
{
	struct vfio_device *vdev = df->device;

	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->noiommu) {
		vfio_iommufd_noiommu_unbind(vdev);
		return;
	}

	if (vdev->ops->unbind_iommufd)
		vdev->ops->unbind_iommufd(vdev);
}

int vfio_iommufd_attach(struct vfio_device *vdev, u32 *pt_id)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->noiommu)
		return 0;

	return vdev->ops->attach_ioas(vdev, pt_id);
}

void vfio_iommufd_detach(struct vfio_device *vdev)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (!vdev->noiommu)
		vdev->ops->detach_ioas(vdev);
}

struct iommufd_ctx *vfio_iommufd_physical_ictx(struct vfio_device *vdev)
{
	if (vdev->iommufd_device)
		return iommufd_device_to_ictx(vdev->iommufd_device);
	if (vdev->noiommu_access)
		return iommufd_access_to_ictx(vdev->noiommu_access);
	return NULL;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_ictx);

int vfio_iommufd_physical_devid(struct vfio_device *vdev)
{
	if (vdev->iommufd_device)
		return iommufd_device_to_id(vdev->iommufd_device);
	if (vdev->noiommu_access)
		return iommufd_access_to_id(vdev->noiommu_access);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_devid);

/*
 * The physical standard ops mean that the iommufd_device is bound to the
 * physical device vdev->dev that was provided to vfio_init_group_dev(). Drivers
 * using this ops set should call vfio_register_group_dev()
 */
int vfio_iommufd_physical_bind(struct vfio_device *vdev,
			       struct iommufd_ctx *ictx, u32 *out_device_id)
{
	struct iommufd_device *idev;

	idev = iommufd_device_bind(ictx, vdev->dev, out_device_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);
	vdev->iommufd_device = idev;
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_bind);

void vfio_iommufd_physical_unbind(struct vfio_device *vdev)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->iommufd_attached) {
		iommufd_device_detach(vdev->iommufd_device);
		vdev->iommufd_attached = false;
	}
	iommufd_device_unbind(vdev->iommufd_device);
	vdev->iommufd_device = NULL;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_unbind);

int vfio_iommufd_physical_attach_ioas(struct vfio_device *vdev, u32 *pt_id)
{
	int rc;

	lockdep_assert_held(&vdev->dev_set->lock);

	if (WARN_ON(!vdev->iommufd_device))
		return -EINVAL;

	if (vdev->iommufd_attached)
		rc = iommufd_device_replace(vdev->iommufd_device, pt_id);
	else
		rc = iommufd_device_attach(vdev->iommufd_device, pt_id);
	if (rc)
		return rc;
	vdev->iommufd_attached = true;
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_attach_ioas);

void vfio_iommufd_physical_detach_ioas(struct vfio_device *vdev)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (WARN_ON(!vdev->iommufd_device) || !vdev->iommufd_attached)
		return;

	iommufd_device_detach(vdev->iommufd_device);
	vdev->iommufd_attached = false;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_detach_ioas);

/*
 * The emulated standard ops mean that vfio_device is going to use the
 * "mdev path" and will call vfio_pin_pages()/vfio_dma_rw(). Drivers using this
 * ops set should call vfio_register_emulated_iommu_dev(). Drivers that do
 * not call vfio_pin_pages()/vfio_dma_rw() have no need to provide dma_unmap.
 */

static void vfio_emulated_unmap(void *data, unsigned long iova,
				unsigned long length)
{
	struct vfio_device *vdev = data;

	if (vdev->ops->dma_unmap)
		vdev->ops->dma_unmap(vdev, iova, length);
}

static const struct iommufd_access_ops vfio_user_ops = {
	.needs_pin_pages = 1,
	.unmap = vfio_emulated_unmap,
};

int vfio_iommufd_emulated_bind(struct vfio_device *vdev,
			       struct iommufd_ctx *ictx, u32 *out_device_id)
{
	struct iommufd_access *user;

	lockdep_assert_held(&vdev->dev_set->lock);

	user = iommufd_access_create(ictx, &vfio_user_ops, vdev, out_device_id);
	if (IS_ERR(user))
		return PTR_ERR(user);
	vdev->iommufd_access = user;
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_emulated_bind);

void vfio_iommufd_emulated_unbind(struct vfio_device *vdev)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->iommufd_access) {
		iommufd_access_destroy(vdev->iommufd_access);
		vdev->iommufd_attached = false;
		vdev->iommufd_access = NULL;
	}
}
EXPORT_SYMBOL_GPL(vfio_iommufd_emulated_unbind);

int vfio_iommufd_emulated_attach_ioas(struct vfio_device *vdev, u32 *pt_id)
{
	int rc;

	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->iommufd_attached)
		rc = iommufd_access_replace(vdev->iommufd_access, *pt_id);
	else
		rc = iommufd_access_attach(vdev->iommufd_access, *pt_id);
	if (rc)
		return rc;
	vdev->iommufd_attached = true;
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_emulated_attach_ioas);

void vfio_iommufd_emulated_detach_ioas(struct vfio_device *vdev)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (WARN_ON(!vdev->iommufd_access) || !vdev->iommufd_attached)
		return;

	iommufd_access_detach(vdev->iommufd_access);
	vdev->iommufd_attached = false;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_emulated_detach_ioas);
