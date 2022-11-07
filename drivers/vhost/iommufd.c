// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/vdpa.h>
#include <linux/iommufd.h>

#include "vhost.h"

MODULE_IMPORT_NS(IOMMUFD);

int vdpa_iommufd_bind(struct vdpa_device *vdpa, struct iommufd_ctx *ictx,
		      u32 *ioas_id, u32 *device_id)
{
	int ret;

	vhost_vdpa_lockdep_assert_held(vdpa);

	/*
	 * If the driver doesn't provide this op then it means the device does
	 * not do DMA at all. So nothing to do.
	 */
	if (!vdpa->config->bind_iommufd)
		return 0;

	ret = vdpa->config->bind_iommufd(vdpa, ictx, device_id);
	if (ret)
		return ret;

	ret = vdpa->config->attach_ioas(vdpa, ioas_id);
	if (ret)
		goto err_unbind;
	vdpa->iommufd_attached = true;

	/*
	 * The legacy path has no way to return the device id or the selected
	 * pt_id
	 */
	return 0;

err_unbind:
	if (vdpa->config->unbind_iommufd)
		vdpa->config->unbind_iommufd(vdpa);
	return ret;
}

void vdpa_iommufd_unbind(struct vdpa_device *vdpa)
{
	vhost_vdpa_lockdep_assert_held(vdpa);

	if (vdpa->config->unbind_iommufd)
		vdpa->config->unbind_iommufd(vdpa);
}


int vdpa_iommufd_physical_bind(struct vdpa_device *vdpa,
			       struct iommufd_ctx *ictx, u32 *out_device_id)
{
	struct device *dma_dev = vdpa_get_dma_dev(vdpa);
	struct iommufd_device *idev;

	idev = iommufd_device_bind(ictx, dma_dev, out_device_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);
	vdpa->iommufd_device = idev;
	return 0;
}
EXPORT_SYMBOL_GPL(vdpa_iommufd_physical_bind);

void vdpa_iommufd_physical_unbind(struct vdpa_device *vdpa)
{
	vhost_vdpa_lockdep_assert_held(vdpa);

	if (vdpa->iommufd_attached) {
		iommufd_device_detach(vdpa->iommufd_device);
		vdpa->iommufd_attached = false;
	}
	iommufd_device_unbind(vdpa->iommufd_device);
	vdpa->iommufd_device = NULL;
}
EXPORT_SYMBOL_GPL(vdpa_iommufd_physical_unbind);

int vdpa_iommufd_physical_attach_ioas(struct vdpa_device *vdpa, u32 *pt_id)
{
	unsigned int flags = 0;

	return iommufd_device_attach(vdpa->iommufd_device, pt_id, flags);
}
EXPORT_SYMBOL_GPL(vdpa_iommufd_physical_attach_ioas);

static void vdpa_emulated_unmap(void *data, unsigned long iova,
				unsigned long length)
{
	struct vdpa_device *vdpa = data;

	vdpa->config->dma_unmap(vdpa, 0 /* FIXME: asid*/, iova, length);
}

static const struct iommufd_access_ops vdpa_user_ops = {
	.needs_pin_pages = 1,
	.unmap = vdpa_emulated_unmap,
};

int vdpa_iommufd_emulated_bind(struct vdpa_device *vdpa,
			       struct iommufd_ctx *ictx, u32 *out_device_id)
{
	vhost_vdpa_lockdep_assert_held(vdpa);

	vdpa->iommufd_ictx = ictx;
	iommufd_ctx_get(ictx);
	return 0;
}
EXPORT_SYMBOL_GPL(vdpa_iommufd_emulated_bind);

void vdpa_iommufd_emulated_unbind(struct vdpa_device *vdpa)
{
	vhost_vdpa_lockdep_assert_held(vdpa);

	if (vdpa->iommufd_access) {
		iommufd_access_destroy(vdpa->iommufd_access);
		vdpa->iommufd_access = NULL;
	}
	iommufd_ctx_put(vdpa->iommufd_ictx);
	vdpa->iommufd_ictx = NULL;
}
EXPORT_SYMBOL_GPL(vdpa_iommufd_emulated_unbind);

int vdpa_iommufd_emulated_attach_ioas(struct vdpa_device *vdpa, u32 *pt_id)
{
	struct iommufd_access *user;

	vhost_vdpa_lockdep_assert_held(vdpa);

	user = iommufd_access_create(vdpa->iommufd_ictx, *pt_id, &vdpa_user_ops,
				     vdpa);
	if (IS_ERR(user))
		return PTR_ERR(user);
	vdpa->iommufd_access = user;
	return 0;
}
EXPORT_SYMBOL_GPL(vdpa_iommufd_emulated_attach_ioas);
