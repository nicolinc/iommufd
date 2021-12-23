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

/*
 * FIXME I'm testing with CONFIG_VFIO=m and seeing problems with CONFIG_IOMMUFD=m
 *   depmod: ERROR: Cycle detected: iommufd -> vfio -> iommufd
 *   depmod: ERROR: Found 2 modules in dependency cycles!
 *
 * So duplicating the followings from VFIO for now:
 *	vfio_info_cap_shift2
 *	vfio_info_cap_add2
 *	vfio_iommu_iova_add_cap
 */
static void vfio_info_cap_shift2(struct vfio_info_cap *caps, size_t offset)
{
	struct vfio_info_cap_header *tmp;
	void *buf = (void *)caps->buf;

	for (tmp = buf; tmp->next; tmp = buf + tmp->next - offset)
		tmp->next += offset;
}

static struct vfio_info_cap_header *vfio_info_cap_add2(struct vfio_info_cap *caps,
					       size_t size, u16 id, u16 version)
{
	void *buf;
	struct vfio_info_cap_header *header, *tmp;

	buf = krealloc(caps->buf, caps->size + size, GFP_KERNEL);
	if (!buf) {
		kfree(caps->buf);
		caps->size = 0;
		return ERR_PTR(-ENOMEM);
	}

	caps->buf = buf;
	header = buf + caps->size;

	/* Eventually copied to user buffer, zero */
	memset(header, 0, size);

	header->id = id;
	header->version = version;

	/* Add to the end of the capability chain */
	for (tmp = buf; tmp->next; tmp = buf + tmp->next)
		; /* nothing */

	tmp->next = caps->size;
	caps->size += size;

	return header;
}

static int vfio_iommu_iova_add_cap(struct vfio_info_cap *caps,
		 struct vfio_iommu_type1_info_cap_iova_range *cap_iovas,
		 size_t size)
{
	struct vfio_info_cap_header *header;
	struct vfio_iommu_type1_info_cap_iova_range *iova_cap;

	header = vfio_info_cap_add2(caps, size,
				   VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE, 1);
	if (IS_ERR(header))
		return PTR_ERR(header);

	iova_cap = container_of(header,
				struct vfio_iommu_type1_info_cap_iova_range,
				header);
	iova_cap->nr_iovas = cap_iovas->nr_iovas;
	memcpy(iova_cap->iova_ranges, cap_iovas->iova_ranges,
	       cap_iovas->nr_iovas * sizeof(*cap_iovas->iova_ranges));
	return 0;
}

static int vfio_iommu_iova_build_caps(struct iommufd_ioas_pagetable *ioaspt,
				      struct vfio_info_cap *caps)
{
	struct vfio_iommu_type1_info_cap_iova_range *cap_iovas;
	struct interval_tree_span_iter span;
	int iovas = 0, i = 0, rc;
	size_t size;

	for (interval_tree_span_iter_first(
		     &span, &ioaspt->iopt.reserved_iova_itree, 0, ULONG_MAX);
	     !interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span)) {
		if (!span.is_hole)
			continue;
		iovas++;
	}

	if (!iovas) {
		/*
		 * Return 0 as a container with a single mdev device
		 * will have an empty list
		 */
		return 0;
	}

	size = struct_size(cap_iovas, iova_ranges, iovas);

	cap_iovas = kzalloc(size, GFP_KERNEL);
	if (!cap_iovas)
		return -ENOMEM;

	cap_iovas->nr_iovas = iovas;

	for (interval_tree_span_iter_first(
		     &span, &ioaspt->iopt.reserved_iova_itree, 0, ULONG_MAX);
	     !interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span)) {
		if (!span.is_hole)
			continue;
		BUG_ON(i > iovas);
		cap_iovas->iova_ranges[i].start = (u64)span.start_hole;
		cap_iovas->iova_ranges[i].end = (u64)span.last_hole;
		i++;
	}

	rc = vfio_iommu_iova_add_cap(caps, cap_iovas, size);

	kfree(cap_iovas);
	return rc;
}

static int vfio_iommu_get_info(struct iommufd_ctx *ictx, unsigned long arg)
{
	struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
	struct iommufd_ioas_pagetable *ioaspt;
	struct vfio_iommu_type1_info info;
	unsigned long minsz, capsz;
	int rc;

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

	ioaspt = get_compat_ioas(ictx);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	down_write(&ioaspt->iopt.rwsem);
	info.flags = VFIO_IOMMU_INFO_PGSIZES;

	info.iova_pgsizes = ioaspt->iopt.iova_alignment;

	/*
	 * FIXME support for followings?
	 *
	 * vfio_iommu_migration_build_caps(iommu, &caps);
	 *
	 * if (!rc)
	 *	rc = vfio_iommu_dma_avail_build_caps(iommu, &caps);
	 */

	rc = vfio_iommu_iova_build_caps(ioaspt, &caps);

	up_write(&ioaspt->iopt.rwsem);

	if (rc)
		goto out_put;

	if (caps.size) {
		info.flags |= VFIO_IOMMU_INFO_CAPS;

		if (info.argsz < sizeof(info) + caps.size) {
			info.argsz = sizeof(info) + caps.size;
		} else {
			vfio_info_cap_shift2(&caps, sizeof(info));
			if (copy_to_user((void __user *)arg +
					sizeof(info), caps.buf,
					caps.size)) {
				kfree(caps.buf);
				rc = -EFAULT;
				goto out_put;
			}
			info.cap_offset = sizeof(info);
		}

		kfree(caps.buf);
	}

	rc = copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;

out_put:
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
