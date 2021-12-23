// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES
 */

#include <linux/file.h>
#include <linux/interval_tree.h>
#include <linux/iommu.h>
#include <linux/iommufd.h>
#include <linux/slab.h>
#include <linux/vfio.h>
#include <uapi/linux/vfio.h>

#include "iommufd_private.h"

static bool lock_obj(struct iommufd_object *obj)
{
	/* FIXME this could be in an inline and shared with iommufd_get_object */
	if (!down_read_trylock(&obj->destroy_rwsem))
		return false;
	if (!refcount_inc_not_zero(&obj->users)) {
		up_read(&obj->destroy_rwsem);
		return false;
	}
	return true;
}

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

static int vfio_dma_do_map(struct iommufd_ioas_pagetable *ioaspt,
			   struct vfio_iommu_type1_dma_map *map)
{
	struct iommu_ioas_pagetable_map cmd = {
		.size = sizeof(cmd),
		.user_va = map->vaddr,
		.length = map->size,
		.iova = map->iova,
	};

	if (map->flags & VFIO_DMA_MAP_FLAG_READ)
		cmd.flags |= IOMMU_IOAS_PAGETABLE_MAP_READABLE;
	if (map->flags & VFIO_DMA_MAP_FLAG_WRITE)
		cmd.flags |= IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE;
	/* FIXME if (map->flags & VFIO_DMA_MAP_FLAG_VADDR) ?*/
	cmd.flags |= IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA;

	return __iommufd_ioas_pagetable_map(ioaspt, &cmd);
}

static int vfio_map_dma(struct iommufd_ctx *ictx, unsigned int cmd,
			unsigned long arg)
{
	uint32_t mask = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE |
			VFIO_DMA_MAP_FLAG_VADDR;
	struct iommufd_ioas_pagetable *ioaspt;
	struct vfio_iommu_type1_dma_map map;
	unsigned long minsz;
	int rc;

	minsz = offsetofend(struct vfio_iommu_type1_dma_map, size);

	if (copy_from_user(&map, (void __user *)arg, minsz))
		return -EFAULT;

	if (map.argsz < minsz || map.flags & ~mask)
		return -EINVAL;

	ioaspt = get_compat_ioas(ictx);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	rc = vfio_dma_do_map(ioaspt, &map);

	iommufd_put_object(&ioaspt->obj);

	return rc;
}

static int vfio_dma_do_unmap(struct iommufd_ioas_pagetable *ioaspt,
			     struct vfio_iommu_type1_dma_unmap *unmap)
{
	if (unmap->flags & VFIO_DMA_UNMAP_FLAG_ALL)
		return iopt_unmap_all(&ioaspt->iopt);
	else if (unmap->flags & VFIO_DMA_UNMAP_FLAG_VADDR)
		return -EOPNOTSUPP;
	else
		return iopt_unmap_iova(&ioaspt->iopt, unmap->iova, unmap->size);
}

static int vfio_unmap_dma(struct iommufd_ctx *ictx, unsigned int cmd,
			  unsigned long arg)
{
	uint32_t mask = VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP |
			VFIO_DMA_UNMAP_FLAG_VADDR |
			VFIO_DMA_UNMAP_FLAG_ALL;
	struct vfio_iommu_type1_dma_unmap unmap;
	struct iommufd_ioas_pagetable *ioaspt;
	unsigned long minsz;
	int rc;

	minsz = offsetofend(struct vfio_iommu_type1_dma_unmap, size);

	if (copy_from_user(&unmap, (void __user *)arg, minsz))
		return -EFAULT;

	if (unmap.argsz < minsz || unmap.flags & ~mask)
		return -EINVAL;

	if ((unmap.flags & VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP) &&
	    (unmap.flags & (VFIO_DMA_UNMAP_FLAG_ALL |
			    VFIO_DMA_UNMAP_FLAG_VADDR)))
		return -EINVAL;

	if (unmap.flags & VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP)
		return -EOPNOTSUPP;

	ioaspt = get_compat_ioas(ictx);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	rc = vfio_dma_do_unmap(ioaspt, &unmap);

	iommufd_put_object(&ioaspt->obj);

	return rc;
}

static int vfio_check_extension(unsigned long type)
{
	switch (type) {
	case VFIO_TYPE1_IOMMU:
	case VFIO_TYPE1v2_IOMMU:
	case VFIO_TYPE1_NESTING_IOMMU:
	case VFIO_UNMAP_ALL:
		return 1;
	case VFIO_DMA_CC_IOMMU:
	case VFIO_UPDATE_VADDR:
	default:
		return 0;
	}
}

static int vfio_set_iommu(struct iommufd_ctx *ictx, unsigned long type)
{
	if (!vfio_check_extension(type))
		return -ENODEV;

	return 0;
}

static int vfio_iommu_get_info(struct iommufd_ctx *ictx, unsigned long arg)
{
	struct vfio_iommu_type1_info_cap_iova_range *cap_iovas;
	struct iommufd_ioas_pagetable *ioaspt;
	struct interval_tree_span_iter span;
	struct vfio_iommu_type1_info info;
	unsigned long minsz, capsz;
	int max_iovas = 0;
	int iovas = 0;
	int i = 0, rc;
	size_t size;

	minsz = offsetofend(struct vfio_iommu_type1_info, iova_pgsizes);

	/* For backward compatibility, cannot require this */
	capsz = offsetofend(struct vfio_iommu_type1_info, cap_offset);

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	if (info.argsz >= capsz) {
		minsz = capsz;
		info.cap_offset = 0; /* output, no-recopy necessary */
	}

	/* Calculate how many iova_ranges does user space allow us to return */
	if (info.argsz > sizeof(info) + sizeof(*cap_iovas)) {
		max_iovas = info.argsz - sizeof(info) - sizeof(*cap_iovas);
		if (max_iovas % sizeof(cap_iovas->iova_ranges[0]))
			return -EINVAL;
		max_iovas /= sizeof(cap_iovas->iova_ranges[0]);
	}

	ioaspt = get_compat_ioas(ictx);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	down_read(&ioaspt->iopt.rwsem);
	info.flags = VFIO_IOMMU_INFO_PGSIZES;
	info.iova_pgsizes = ioaspt->iopt.iova_alignment;

	for (interval_tree_span_iter_first(
		     &span, &ioaspt->iopt.reserved_iova_itree, 0, ULONG_MAX);
	     !interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span)) {
		if (!span.is_hole)
			continue;
		iovas++;
	}

	if (iovas == 0)
		goto out_copy;

	if (max_iovas == 0) {
		/* User space is waiting for us to report a size */
		info.argsz += struct_size(cap_iovas, iova_ranges, iovas);
		goto out_copy;
	}

	/* Otherwise, report iovas within the limit of max_iovas */
	iovas = min_t(size_t, iovas, max_iovas);
	size = struct_size(cap_iovas, iova_ranges, iovas);

	cap_iovas = kzalloc(size, GFP_KERNEL);
	if (!cap_iovas) {
		rc = -ENOMEM;
		goto out_put;
	}

	info.cap_offset = sizeof(info);
	info.flags |= VFIO_IOMMU_INFO_CAPS;

	cap_iovas->header.id = VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE;
	cap_iovas->header.version = 1;
	cap_iovas->nr_iovas = iovas;

	for (interval_tree_span_iter_first(
		     &span, &ioaspt->iopt.reserved_iova_itree, 0, ULONG_MAX);
	     !interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span)) {
		if (!span.is_hole)
			continue;
		cap_iovas->iova_ranges[i].start = (u64)span.start_hole;
		cap_iovas->iova_ranges[i].end = (u64)span.last_hole;
		i++;
	}

	rc = copy_to_user((void __user *)arg + sizeof(info), cap_iovas, size);
	if (rc) {
		kfree(cap_iovas);
		rc = -EFAULT;
		goto out_put;
	}

	kfree(cap_iovas);

out_copy:
	rc = copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;

out_put:
	up_read(&ioaspt->iopt.rwsem);
	iommufd_put_object(&ioaspt->obj);

	return rc;
}

/* FIXME TODO:
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
	case VFIO_SET_IOMMU:
		return vfio_set_iommu(ictx, arg);
	case VFIO_CHECK_EXTENSION:
		return vfio_check_extension(arg);
	case VFIO_IOMMU_GET_INFO:
		return vfio_iommu_get_info(ictx, arg);
	case VFIO_IOMMU_MAP_DMA:
		return vfio_map_dma(ictx, cmd, arg);
	case VFIO_IOMMU_UNMAP_DMA:
		return vfio_unmap_dma(ictx, cmd, arg);
	case VFIO_IOMMU_DIRTY_PAGES:
	default:
		return -ENOIOCTLCMD;
	}
	return -ENOIOCTLCMD;
}

static int iommufd_vfio_pagetable_alloc(struct iommufd_ctx *ictx,
					struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_pagetable_alloc *alloc = ucmd->cmd;
	struct iommufd_ioas_pagetable* ioaspt;

	ioaspt = __iommufd_ioas_pagetable_alloc(ucmd);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	alloc->out_ioas_id = ioaspt->obj.id;
	ictx->vfio_ioaspt = ioaspt;

	return 0;
}

struct iommufd_ctx *vfio_group_set_iommufd(int fd, struct list_head *device_list)
{
	struct vfio_device_attach_ioaspt attach = { .argsz = sizeof(attach) };
	struct iommu_ioas_pagetable_alloc alloc = { .size = sizeof(alloc) };
	struct vfio_device_bind_iommufd bind = { .argsz = sizeof(bind) };
	struct iommufd_ctx *ictx = iommufd_fget(fd);
	struct vfio_device *device;
	struct iommufd_ucmd ucmd = {
		.cmd = &alloc,
		.ictx = ictx,
	};
	int rc;

	if (!ictx)
		return ictx;

	ictx->vfio_fd = fd;

	/* FIXME bind.dev_cookie */
	bind.iommufd = fd;
	attach.iommufd = fd;

	/*
	 * FIXME get_compat_ioas() should have hanlded allocation too
	 * yet it is having a locking bug, so I'm working around here.
	 * We'd need to share allocation code anyway, as FIXME remarks
	 * in get_compat_ioas().
	 */
	rc = iommufd_vfio_pagetable_alloc(ictx, &ucmd);
	if (ucmd.new_object) {
		if (rc)
			iommufd_object_abort(ictx, ucmd.new_object);
		else
			iommufd_object_finalize(ictx, ucmd.new_object);
	}
	if (rc)
		goto out_fput;

	attach.ioaspt_id = alloc.out_ioas_id;

	list_for_each_entry(device, device_list, group_next) {
		if (!device->ops->bind_iommufd || !device->ops->unbind_iommufd)
			goto detach_ioaspt;

		rc = device->ops->bind_iommufd(device, &bind);
		if (rc)
			goto detach_ioaspt;

		if (unlikely(!device->ops->attach_ioaspt)) {
			goto detach_ioaspt;
		}

		rc = device->ops->attach_ioaspt(device, &attach);
		if (rc)
			goto detach_ioaspt;
	}

	return ictx;

detach_ioaspt:
	list_for_each_entry(device, device_list, group_next) {
		struct vfio_device_detach_ioaspt detach = {
			.argsz = sizeof(detach),
			.ioaspt_id = alloc.out_ioas_id,
			.iommufd = fd,
		};
		device->ops->detach_ioaspt(device, &detach);
		device->ops->unbind_iommufd(device);
	}
	/* FIXME Something is wrong here causing WARN_ONs... */
	iommufd_ioas_pagetable_destroy(&ictx->vfio_ioaspt->obj);
out_fput:
	fput(ictx->filp);

	return NULL;
}
EXPORT_SYMBOL_GPL(vfio_group_set_iommufd);

void vfio_group_unset_iommufd(void *iommufd, struct list_head *device_list)
{
	struct iommufd_ctx *ictx = (struct iommufd_ctx *)iommufd;
	struct vfio_device *device;

	if (!ictx)
		return;

	if (!ictx->vfio_ioaspt)
		return;

	list_for_each_entry(device, device_list, group_next) {
		struct vfio_device_detach_ioaspt detach = {
			.argsz = sizeof(detach),
			.ioaspt_id = ictx->vfio_ioaspt->obj.id,
			.iommufd = ictx->vfio_fd,
		};
		if (device->ops->detach_ioaspt)
			device->ops->detach_ioaspt(device, &detach);
		if (device->ops->unbind_iommufd)
			device->ops->unbind_iommufd(device);
	}

	/* FIXME Something is wrong here causing WARN_ONs... */
	iommufd_ioas_pagetable_destroy(&ictx->vfio_ioaspt->obj);
	fput(ictx->filp);
}
EXPORT_SYMBOL_GPL(vfio_group_unset_iommufd);
