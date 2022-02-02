// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */

#include <linux/file.h>
#include <linux/interval_tree.h>
#include <linux/iommu.h>
#include <linux/iommufd.h>
#include <linux/slab.h>
#include <linux/vfio.h>
#include <uapi/linux/vfio.h>
#include <uapi/linux/iommufd.h>

#include "iommufd_private.h"

static struct iommufd_ioas_pagetable *get_compat_ioas(struct iommufd_ctx *ictx)
{
	struct iommufd_ioas_pagetable *ioaspt = ERR_PTR(-EINVAL);

	xa_lock(&ictx->objects);
	if (ictx->vfio_ioaspt && lock_obj(&ictx->vfio_ioaspt->obj)) {
		ioaspt = ictx->vfio_ioaspt;
		xa_unlock(&ictx->objects);
		return ioaspt;
	}
	xa_unlock(&ictx->objects);

	return ioaspt;
}

static struct iommufd_ioas_pagetable *
alloc_compat_ioas(struct iommufd_ctx *ictx)
{
	struct iommufd_ioas_pagetable *out_ioaspt;
	struct iommufd_ioas_pagetable *ioaspt;

	ioaspt = __iommufd_ioas_pagetable_alloc(ictx);
	if (IS_ERR(ioaspt))
		return ioaspt;

	xa_lock(&ictx->objects);
	if (ictx->vfio_ioaspt && lock_obj(&ictx->vfio_ioaspt->obj))
		out_ioaspt = ictx->vfio_ioaspt;
	else
		out_ioaspt = ioaspt;
	xa_unlock(&ictx->objects);

	if (out_ioaspt == ioaspt) {
		if (!lock_obj(&out_ioaspt->obj))
			WARN_ON(true);
		iommufd_object_finalize(ictx, &ioaspt->obj);
	} else {
		iommufd_object_abort(ictx, &ioaspt->obj);
	}
	return out_ioaspt;
}

static int vfio_map_dma(struct iommufd_ctx *ictx, unsigned int cmd,
			unsigned long arg)
{
	u32 supported_flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
	size_t minsz = offsetofend(struct vfio_iommu_type1_dma_map, size);
	struct iommufd_ioas_pagetable *ioaspt;
	struct vfio_iommu_type1_dma_map map;
	int iommu_prot = IOMMU_CACHE;
	int rc;

	if (copy_from_user(&map, (void __user *)arg, minsz))
		return -EFAULT;

	if (map.argsz < minsz || map.flags & ~supported_flags)
		return -EINVAL;

	if (map.flags & VFIO_DMA_MAP_FLAG_READ)
		iommu_prot |=IOMMU_READ;
	if (map.flags & VFIO_DMA_MAP_FLAG_WRITE)
		iommu_prot |=IOMMU_WRITE;

	ioaspt = get_compat_ioas(ictx);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	down_write(&ioaspt->iopt.rwsem);
	rc = iopt_map_user_pages(&ioaspt->iopt, map.iova,
				 u64_to_user_ptr(map.vaddr), map.size,
				 iommu_prot);
	up_write(&ioaspt->iopt.rwsem);
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
	/*
	 * FIXME: The type1 iommu allows splitting of maps. This is doable but
	 * is a bunch of extra code that is only for supporting this case.
	 */
	case VFIO_TYPE1_IOMMU:
		return 0;
	case VFIO_TYPE1v2_IOMMU:
	case VFIO_UNMAP_ALL:
		return 1;
	/*
	 * FIXME: No idea what VFIO_TYPE1_NESTING_IOMMU does as far as the uAPI
	 * is concerned. Seems like it was never completed, it only does
	 * something on ARM, but I can't figure out what or how to use it. Can't
	 * find any user implementation either.
	 */
	case VFIO_TYPE1_NESTING_IOMMU:
	/*
	 * FIXME: Easy to support, but needs rework in the Intel iommu driver
	 * to expose the no snoop squashing to iommufd
	 */
	case VFIO_DMA_CC_IOMMU:
	/*
	 * FIXME: VFIO_DMA_MAP_FLAG_VADDR
	 * https://lore.kernel.org/kvm/1611939252-7240-1-git-send-email-steven.sistare@oracle.com/
	 * Wow, what a wild feature. This should have been implemented by
	 * allowing a iopt_pages to be associated with a memfd. It can then
	 * source mapping requests directly from a memfd without going through a
	 * mm_struct and thus doesn't care that the original qemu exec'd itself.
	 * The idea that userspace can flip a flag and cause kernel users to
	 * block indefinately is unacceptable.
	 *
	 * For VFIO compat we should implement this in a slightly different way,
	 * Creating a access_user that spans the whole area will immediately
	 * stop new faults as they will be handled from the xarray. We can then
	 * reparent the iopt_pages to the new mm_struct and undo the
	 * access_user. No blockage of kernel users required, does require
	 * filling the xarray with pages though.
	 */
	case VFIO_UPDATE_VADDR:
	default:
		return 0;
	}

/* FIXME: VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP I think everything with dirty
  * tracking should be in its own ioctl, not muddled in unmap. If we want to
  * atomically unmap and get the dirty bitmap it should be a flag in the dirty
  * tracking ioctl, not here in unmap. Overall dirty tracking needs a careful
  * review along side HW drivers implementing it.
  */
}

static int vfio_set_iommu(struct iommufd_ctx *ictx, unsigned long type)
{
	struct iommufd_ioas_pagetable *ioaspt;

	if (!vfio_check_extension(type))
		return -ENODEV;

	ioaspt = get_compat_ioas(ictx);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	iommufd_put_object(&ioaspt->obj);

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

	/* Calculate how many iova_ranges user space allows us to return */
	if (info.argsz > sizeof(info) + sizeof(*cap_iovas)) {
		max_iovas = info.argsz - sizeof(info) - sizeof(*cap_iovas);
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

#define vfio_device_detach_unbind(ictx, id, device, device_list)               \
	({                                                                     \
		list_for_each_entry(device, device_list, group_next) {         \
			struct vfio_device_detach_ioaspt detach = {            \
				.argsz = sizeof(detach),                       \
				.ioaspt_id = id,                               \
				.iommufd = ictx->vfio_fd,                      \
			};                                                     \
			if (device->ops->detach_ioaspt)                        \
				device->ops->detach_ioaspt(device, &detach);   \
			if (device->ops->unbind_iommufd)                       \
				device->ops->unbind_iommufd(device);           \
		}                                                              \
	})

struct iommufd_ctx *vfio_group_set_iommufd(int fd, struct list_head *device_list)
{
	struct vfio_device_attach_ioaspt attach = { .argsz = sizeof(attach) };
	struct vfio_device_bind_iommufd bind = { .argsz = sizeof(bind) };
	struct iommufd_ctx *ictx = iommufd_fget(fd);
	struct iommufd_ioas_pagetable *ioaspt;
	struct vfio_device *device;
	int rc;

	if (!ictx)
		return ictx;

	ictx->vfio_fd = fd;

	/*
	 * Note: bind.dev_cookie is designed for page fault, whose uAPI is TBD
	 * on IOMMUFD. And VFIO does not support that either. So we here leave
	 * the dev_cookie to 0 for now, until it is available in VFIO too.
	 */
	bind.dev_cookie = 0;
	bind.iommufd = fd;
	attach.iommufd = fd;

	ioaspt = alloc_compat_ioas(ictx);
	if (IS_ERR(ioaspt)) {
		xa_unlock(&ictx->objects);
		goto out_fput;
	}

	xa_lock(&ictx->objects);
	ictx->vfio_ioaspt = ioaspt;
	attach.ioaspt_id = ioaspt->obj.id;
	xa_unlock(&ictx->objects);

	iommufd_put_object(&ioaspt->obj);

	list_for_each_entry(device, device_list, group_next) {
		if (!device->ops->bind_iommufd || !device->ops->unbind_iommufd)
			goto cleanup_ioaspt;

		rc = device->ops->bind_iommufd(device, &bind);
		if (rc)
			goto cleanup_ioaspt;

		if (unlikely(!device->ops->attach_ioaspt)) {
			goto cleanup_ioaspt;
		}

		rc = device->ops->attach_ioaspt(device, &attach);
		if (rc)
			goto cleanup_ioaspt;
	}

	return ictx;

cleanup_ioaspt:
	vfio_device_detach_unbind(ictx, attach.ioaspt_id, device, device_list);
	iommufd_ioas_pagetable_destroy(&ioaspt->obj);
out_fput:
	fput(ictx->filp);

	return NULL;
}
EXPORT_SYMBOL_GPL(vfio_group_set_iommufd);

void vfio_group_unset_iommufd(void *iommufd, struct list_head *device_list)
{
	struct iommufd_ctx *ictx = (struct iommufd_ctx *)iommufd;
	struct iommufd_ioas_pagetable *ioaspt;
	struct vfio_device *device;
	unsigned int ioaspt_id;

	if (!ictx)
		return;

	ioaspt = get_compat_ioas(ictx);
	if (IS_ERR(ioaspt))
		return;
	ioaspt_id = ioaspt->obj.id;
	iommufd_put_object(&ioaspt->obj);

	vfio_device_detach_unbind(ictx, ioaspt_id, device, device_list);
	iommufd_ioas_pagetable_destroy(&ioaspt->obj);
	fput(ictx->filp);
}
EXPORT_SYMBOL_GPL(vfio_group_unset_iommufd);
