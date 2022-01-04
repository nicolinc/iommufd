// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES
 */

#include <uapi/linux/vfio.h>

#include "iommufd_private.h"

static struct iommufd_ioas_pagetable *get_compat_ioas(struct iommufd_ctx *ictx)
{
	struct iommufd_ioas_pagetable *ioaspt = NULL;
	struct iommufd_ioas_pagetable *out_ioaspt;
	int rc;

	xa_lock(&ictx->objects);
	if (ictx->vfio_ioaspt && lock_obj(&ictx->vfio_ioaspt->obj)) {
		ioaspt = ictx->vfio_ioaspt;
		xa_unlock(&ictx->objects);
		return ioaspt;
	}
	xa_unlock(&ictx->objects);

	ioaspt = iommufd_object_alloc(ictx, ioaspt, IOMMUFD_OBJ_IOAS_PAGETABLE);
	if (IS_ERR(ioaspt))
		return ioaspt;

	/* FIXME should probably share with iommufd_ioas_pagetable_alloc() */
	rc = iopt_init_table(&ioaspt->iopt);
	if (rc)
		goto out_abort;
	INIT_LIST_HEAD(&ioaspt->auto_domains);

	xa_lock(&ictx->objects);
	if (ictx->vfio_ioaspt && lock_obj(&ictx->vfio_ioaspt->obj))
		out_ioaspt = ictx->vfio_ioaspt;
	else
		out_ioaspt = ioaspt;
	xa_unlock(&ictx->objects);

	if (out_ioaspt == ioaspt)
		iommufd_object_finalize(ictx, &ioaspt->obj);
	else
		iommufd_object_abort(ictx, &ioaspt->obj);
	return out_ioaspt;

out_abort:
	iommufd_object_abort(ictx, &ioaspt->obj);
	return ERR_PTR(rc);
}

static int vfio_map_dma(struct iommufd_ctx *ictx, unsigned int cmd,
			unsigned long arg)
{
	struct iommufd_ioas_pagetable *ioaspt;

	ioaspt = get_compat_ioas(ictx);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	iommufd_put_object(&ioaspt->obj);
	return -EOPNOTSUPP;
}

static int vfio_unmap_dma(struct iommufd_ctx *ictx, unsigned int cmd,
			  unsigned long arg)
{
	return -EOPNOTSUPP;
}

static int type1_ioctl(struct iommufd_ctx *ictx, unsigned int cmd,
		       unsigned long arg)
{
	switch (cmd) {
	case VFIO_CHECK_EXTENSION:
		return -EOPNOTSUPP;
	case VFIO_IOMMU_GET_INFO:
		return -EOPNOTSUPP;
	case VFIO_IOMMU_MAP_DMA:
		return vfio_map_dma(ictx, cmd, arg);
	case VFIO_IOMMU_UNMAP_DMA:
		return vfio_unmap_dma(ictx, cmd, arg);
	case VFIO_IOMMU_DIRTY_PAGES:
		return -ENOIOCTLCMD;
	default:
		return -ENOIOCTLCMD;
	}
}

/* FIXME TODO:
#define VFIO_GET_API_VERSION		_IO(VFIO_TYPE, VFIO_BASE + 0)
#define VFIO_CHECK_EXTENSION		_IO(VFIO_TYPE, VFIO_BASE + 1)
#define VFIO_SET_IOMMU			_IO(VFIO_TYPE, VFIO_BASE + 2)
#define VFIO_IOMMU_GET_INFO _IO(VFIO_TYPE, VFIO_BASE + 12)
#define VFIO_IOMMU_UNMAP_DMA _IO(VFIO_TYPE, VFIO_BASE + 14)
#define VFIO_IOMMU_DIRTY_PAGES             _IO(VFIO_TYPE, VFIO_BASE + 17)

PowerPC SPAPR only:
#define VFIO_IOMMU_ENABLE	_IO(VFIO_TYPE, VFIO_BASE + 15)
#define VFIO_IOMMU_DISABLE	_IO(VFIO_TYPE, VFIO_BASE + 16)
#define VFIO_IOMMU_SPAPR_TCE_GET_INFO	_IO(VFIO_TYPE, VFIO_BASE + 12)
#define VFIO_IOMMU_SPAPR_REGISTER_MEMORY	_IO(VFIO_TYPE, VFIO_BASE + 17)
#define VFIO_IOMMU_SPAPR_UNREGISTER_MEMORY	_IO(VFIO_TYPE, VFIO_BASE + 18)
#define VFIO_IOMMU_SPAPR_TCE_CREATE	_IO(VFIO_TYPE, VFIO_BASE + 19)
#define VFIO_IOMMU_SPAPR_TCE_REMOVE	_IO(VFIO_TYPE, VFIO_BASE + 20)
*/

int iommufd_vfio_ioctl(struct iommufd_ctx *ictx, unsigned int cmd,
		       unsigned long arg)
{
	switch (cmd) {
	case VFIO_GET_API_VERSION:
		return VFIO_API_VERSION;
	case VFIO_CHECK_EXTENSION:
		return -EOPNOTSUPP;
	case VFIO_SET_IOMMU:
		return -EOPNOTSUPP;
	default:
		// FIXME check current 'set_iommu' type
		return type1_ioctl(ictx, cmd, arg);
	}
	return -ENOIOCTLCMD;
}
