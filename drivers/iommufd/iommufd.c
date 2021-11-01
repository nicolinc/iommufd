// SPDX-License-Identifier: GPL-2.0-only
/*
 * I/O Address Space Management for passthrough devices
 *
 * Copyright (C) 2021 Intel Corporation
 *
 * Author: Liu Yi L <yi.l.liu@intel.com>
 */

#define pr_fmt(fmt)    "iommufd: " fmt

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/iommu.h>
#include <linux/iommufd.h>
#include <linux/xarray.h>
#include <asm-generic/bug.h>
#include <linux/vfio.h>

/* Per iommufd */
struct iommufd_ctx {
	struct file *filp;
	struct xarray device_xa; /* xarray of bound devices */
	struct xarray ioas_xa; /* xarray of ioases */
};

/*
 * A iommufd_device object represents the binding relationship
 * between iommufd and device. It is created per a successful
 * binding request from device driver. The bound device must be
 * a physical device so far. Subdevice will be supported later
 * (with additional PASID information). An user-assigned cookie
 * is also recorded to mark the device in the /dev/iommu uAPI.
 */
struct iommufd_device {
	unsigned int devid;
	struct iommufd_ctx *ictx;
	struct device *dev; /* always be the physical device */
	u64 dev_cookie;
};

/* Represent an I/O address space */
struct iommufd_ioas {
	u32 ioas_id;
	u32 type;
	u32 addr_width;
	bool enforce_snoop;
	struct iommufd_ctx *ictx;
	refcount_t refs;
	struct rw_semaphore device_lock;
	struct xarray device;
	struct iommu_domain *domain;
	struct vfio_iommu *vfio_iommu; /* FIXME: added for reusing vfio_iommu_type1 code */
};

/*
 * An ioas_device_info object is created per each successful attaching
 * request. A list of objects are maintained per ioas when the address
 * space is shared by multiple devices.
 */
struct ioas_device_info {
	struct iommufd_device *idev;
	struct list_head next;
};

static int iommufd_fops_open(struct inode *inode, struct file *filp)
{
	struct iommufd_ctx *ictx;
	int ret = 0;

	ictx = kzalloc(sizeof(*ictx), GFP_KERNEL);
	if (!ictx)
		return -ENOMEM;

	xa_init_flags(&ictx->device_xa, XA_FLAGS_ALLOC1);
	xa_init_flags(&ictx->ioas_xa, XA_FLAGS_ALLOC1);
	ictx->filp = filp;
	filp->private_data = ictx;

	return ret;
}

static const struct file_operations iommufd_fops;

/**
 * iommufd_fget - Acquires a reference to the iommufd file.
 * @fd: [in] iommufd file descriptor.
 *
 * Returns a pointer to the file, otherwise NULL;
 *
 */
static struct file *iommufd_fget(int fd)
{
	struct file *filp;

	filp = fget(fd);
	if (!filp)
		return NULL;

	if (filp->f_op != &iommufd_fops) {
		fput(filp);
		return NULL;
	}

	return filp;
}

static struct iommufd_ioas *ioasid_get_ioas(struct iommufd_ctx *ictx,
					    u32 ioas_id)
{
	struct iommufd_ioas *ioas;

	if (ioas_id == IOMMUFD_INVALID_IOAS)
		return NULL;

	ioas = xa_load(&ictx->ioas_xa, ioas_id);
	if (!(ioas && refcount_inc_not_zero(&ioas->refs)))
		ioas = NULL;

	return ioas;
}

static void ioas_put(struct iommufd_ioas *ioas)
{
	struct iommufd_ctx *ictx = ioas->ictx;
	u32 ioas_id = ioas->ioas_id;

	if (!refcount_dec_and_test(&ioas->refs))
		return;

	WARN_ON(!xa_empty(&ioas->device));
	xa_erase(&ictx->ioas_xa, ioas_id);
	vfio_iommu_type1_release(ioas->vfio_iommu); /* FIXME: reused vfio code */
	kfree(ioas);
}

static int iommufd_fops_release(struct inode *inode, struct file *filp)
{
	struct iommufd_ctx *ictx = filp->private_data;
	struct iommufd_ioas *ioas;
	unsigned long index;

	xa_for_each(&ictx->ioas_xa, index, ioas)
		ioas_put(ioas);

	WARN_ON(!xa_empty(&ictx->device_xa));
	WARN_ON(!xa_empty(&ictx->ioas_xa));

	kfree(ictx);

	return 0;
}

static int iommufd_ioas_alloc(struct iommufd_ctx *ictx, unsigned long arg)
{
	struct iommu_ioas_alloc req;
	struct iommufd_ioas *ioas;
	struct vfio_iommu *vfio_iommu;
	unsigned long minsz;
	int ret;

	minsz = offsetofend(struct iommu_ioas_alloc, addr_width);

	if (copy_from_user(&req, (void __user *)arg, minsz))
		return -EFAULT;

	if (req.argsz < minsz || !req.addr_width ||
	    req.flags != IOMMU_IOAS_ENFORCE_SNOOP ||
	    req.type != IOMMU_IOAS_TYPE_KERNEL_TYPE1V2)
		return -EINVAL;

	ioas = kzalloc(sizeof(*ioas), GFP_KERNEL);
	if (!ioas)
		return -ENOMEM;

	/* only supports kernel managed I/O page table so far */
	ioas->type = IOMMU_IOAS_TYPE_KERNEL_TYPE1V2;
	ioas->addr_width = req.addr_width;
	/* only supports enforce snoop today */
	ioas->enforce_snoop = true;
	ioas->ictx = ictx;

	init_rwsem(&ioas->device_lock);
	xa_init_flags(&ioas->device, XA_FLAGS_ALLOC1);

	/* FIXME: get a vfio_iommu object for dma map/unmap management */
	vfio_iommu = vfio_iommu_type1_open(VFIO_TYPE1v2_IOMMU);
	if (IS_ERR(vfio_iommu)) {
		pr_debug("Failed to get vfio_iommu object\n");
		kfree(ioas);
		return PTR_ERR(vfio_iommu);
	}
	ioas->vfio_iommu = vfio_iommu;

	refcount_set(&ioas->refs, 1);

	ret = xa_alloc(&ictx->ioas_xa, &ioas->ioas_id, ioas,
		       xa_limit_32b, GFP_KERNEL);
	if (ret) {
		vfio_iommu_type1_release(vfio_iommu); /* FIXME: reused vfio code */
		kfree(ioas);
	}

	if (copy_to_user((void __user *)arg + minsz,
			 &ioas->ioas_id, sizeof(ioas->ioas_id))) {
		xa_erase(&ictx->ioas_xa, ioas->ioas_id);
		vfio_iommu_type1_release(vfio_iommu); /* FIXME: reused vfio code */
		kfree(ioas);
		ret = -EFAULT;
	}

	return ret;
}

static int iommufd_ioas_free(struct iommufd_ctx *ictx, unsigned long arg)
{
	struct iommufd_ioas *ioas = NULL;
	u32 ioas_id;

	if (copy_from_user(&ioas_id, (void __user *)arg, sizeof(ioas_id)))
		return -EFAULT;

	if (ioas_id == IOMMUFD_INVALID_IOAS)
		return -EINVAL;

	ioas = xa_load(&ictx->ioas_xa, ioas_id);
	if (IS_ERR_OR_NULL(ioas))
		return -EINVAL;

	/* Disallow free if refcount is not 1 */
	if (refcount_read(&ioas->refs) > 1)
		return -EBUSY;

	ioas_put(ioas);

	return 0;
};

static int iommu_device_add_cap_chain(struct device *dev, unsigned long arg,
				      struct iommu_device_info *info)
{
	struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
	int ret;

	ret = vfio_device_add_iova_cap(dev, &caps);
	if (ret)
		return ret;

	if (caps.size) {
		info->flags |= IOMMU_DEVICE_INFO_CAPS;

		if (info->argsz < sizeof(*info) + caps.size) {
			info->argsz = sizeof(*info) + caps.size;
		} else {
			vfio_info_cap_shift(&caps, sizeof(*info));
			if (copy_to_user((void __user *)arg +
					sizeof(*info), caps.buf,
					caps.size)) {
				kfree(caps.buf);
				info->flags &= ~IOMMU_DEVICE_INFO_CAPS;
				return -EFAULT;
			}
			info->cap_offset = sizeof(*info);
		}

		kfree(caps.buf);
	}
	return 0;
}

static void iommu_device_build_info(struct device *dev,
				    struct iommu_device_info *info)
{
	union iommu_devattr_data attr;

	if (!iommu_device_get_info(dev, IOMMU_DEV_INFO_FORCE_SNOOP, &attr))
		info->flags |= attr.force_snoop ? IOMMU_DEVICE_INFO_ENFORCE_SNOOP : 0;

	if (!iommu_device_get_info(dev, IOMMU_DEV_INFO_ADDR_WIDTH, &attr)) {
		info->addr_width = attr.addr_width;
		info->flags |= IOMMU_DEVICE_INFO_ADDR_WIDTH;
	}

	if (!iommu_device_get_info(dev, IOMMU_DEV_INFO_PAGE_SIZE, &attr)) {
		info->pgsize_bitmap = attr.page_size;
		info->flags |= IOMMU_DEVICE_INFO_PGSIZES;
	}
}

static int iommufd_get_device_info(struct iommufd_ctx *ictx,
				   unsigned long arg)
{
	struct iommu_device_info info;
	unsigned long minsz;
	struct iommufd_device *idev;
	int ret;

	minsz = offsetofend(struct iommu_device_info, cap_offset);

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz || info.devid == IOMMUFD_INVALID_DEVID)
		return -EINVAL;

	info.flags = 0;

	idev = xa_load(&ictx->device_xa, info.devid);
	if (!idev)
		return -EINVAL;

	iommu_device_build_info(idev->dev, &info);

	info.cap_offset = 0;
	ret = iommu_device_add_cap_chain(idev->dev, arg, &info);
	if (ret)
		pr_debug("No cap chain added, error %d\n", ret);

	return copy_to_user((void __user *)arg, &info, minsz) ? -EFAULT : 0;
}

static int iommufd_process_dma_op(struct iommufd_ctx *ictx,
				  unsigned long arg, bool map)
{
	struct iommu_ioas_dma_op dma;
	unsigned long minsz;
	struct iommufd_ioas *ioas = NULL;
	int ret;

	minsz = offsetofend(struct iommu_ioas_dma_op, padding);

	if (copy_from_user(&dma, (void __user *)arg, minsz))
		return -EFAULT;

	if (dma.argsz < minsz || dma.flags || dma.ioas < 0)
		return -EINVAL;

	ioas = ioasid_get_ioas(ictx, dma.ioas);
	if (!ioas) {
		pr_err_ratelimited("unkonwn IOASID %u\n", dma.ioas);
		return -EINVAL;
	}

	down_read(&ioas->device_lock);

	/*
	 * Needs to block map/unmap request from userspace before IOAS
	 * is attached to any device.
	 */
	if (xa_empty(&ioas->device)) {
		ret = -EINVAL;
		goto out;
	}

	if (map)
		ret = vfio_iommu_type1_map_dma(ioas->vfio_iommu, arg + minsz);
	else
		ret = vfio_iommu_type1_unmap_dma(ioas->vfio_iommu, arg + minsz);
out:
	up_read(&ioas->device_lock);
	ioas_put(ioas);

	return ret;
};

static long iommufd_fops_unl_ioctl(struct file *filp,
				   unsigned int cmd, unsigned long arg)
{
	struct iommufd_ctx *ictx = filp->private_data;
	long ret = -EINVAL;

	switch (cmd) {
	case IOMMU_CHECK_EXTENSION:
		switch (arg) {
		case EXT_MAP_TYPE1V2:
			return 1;
		default:
			return 0;
		}
	case IOMMU_DEVICE_GET_INFO:
		ret = iommufd_get_device_info(ictx, arg);
		break;
	case IOMMU_IOAS_ALLOC:
		ret = iommufd_ioas_alloc(ictx, arg);
		break;
	case IOMMU_IOAS_FREE:
		ret = iommufd_ioas_free(ictx, arg);
		break;
	case IOMMU_IOAS_MAP_DMA:
		ret = iommufd_process_dma_op(ictx, arg, true);
		break;
	case IOMMU_IOAS_UNMAP_DMA:
		ret = iommufd_process_dma_op(ictx, arg, false);
		break;
	default:
		break;
	}
	return ret;
}

static const struct file_operations iommufd_fops = {
	.owner		= THIS_MODULE,
	.open		= iommufd_fops_open,
	.release	= iommufd_fops_release,
	.unlocked_ioctl	= iommufd_fops_unl_ioctl,
};

static struct miscdevice iommu_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "iommu",
	.fops = &iommufd_fops,
	.nodename = "iommu",
	.mode = 0666,
};

/* Caller should hold write on ioas->device_lock */
static void ioas_free_domain_if_empty(struct iommufd_ioas *ioas)
{
	if (xa_empty(&ioas->device)) {
		iommu_domain_free(ioas->domain);
		ioas->domain = NULL;
	}
}

/* HACK:
 * vfio_iommu_add/remove_device() is hacky implementation for
 * this version to add the device/group to vfio iommu type1.
 */
static int vfio_iommu_add_device(struct vfio_iommu *vfio_iommu,
				 struct device *dev,
				 struct iommu_domain *domain)
{
	struct iommu_group *group;
	int ret;

	group = iommu_group_get(dev);
	if (!group)
		return -EINVAL;

	ret = vfio_iommu_add_group(vfio_iommu, group, domain);
	iommu_group_put(group);
	return ret;
}

static void vfio_iommu_remove_device(struct vfio_iommu *vfio_iommu,
				     struct device *dev)
{
	struct iommu_group *group;

	group = iommu_group_get(dev);
	if (!group)
		return;

	vfio_iommu_remove_group(vfio_iommu, group);
	iommu_group_put(group);
}

static int ioas_check_device_compatibility(struct iommufd_ioas *ioas,
					   struct device *dev)
{
	union iommu_devattr_data attr;
	int ret;

	/*
	 * currently we only support I/O page table with iommu enforce-snoop
	 * format. Attaching a device which doesn't support this format in its
	 * upstreaming iommu is rejected.
	 */
	ret = iommu_device_get_info(dev, IOMMU_DEV_INFO_FORCE_SNOOP, &attr);
	if (ret || !attr.force_snoop)
		return -EINVAL;

	ret = iommu_device_get_info(dev, IOMMU_DEV_INFO_ADDR_WIDTH, &attr);
	if (ret || attr.addr_width < ioas->addr_width)
		return -EINVAL;

	/* TODO: also need to check permitted iova ranges and pgsize bitmap */

	return 0;
}

/**
 * iommufd_device_attach_ioas - attach device to an ioas
 * @idev: [in] Pointer to struct iommufd_device.
 * @ioas: [in] ioas points to an I/O address space.
 *
 * Returns 0 for successful attach, otherwise returns error.
 *
 */
int iommufd_device_attach_ioas(struct iommufd_device *idev, u32 ioas_id)
{
	struct iommufd_ioas *ioas;
	struct ioas_device_info *ioas_dev;
	struct iommu_domain *domain;
	int ret;
	u32 id;

	ioas = ioasid_get_ioas(idev->ictx, ioas_id);
	if (!ioas)
		return -EINVAL;

	down_write(&ioas->device_lock);

	if (xa_load(&ioas->device, idev->devid)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = ioas_check_device_compatibility(ioas, idev->dev);
	if (ret)
		goto out_unlock;

	ioas_dev = kzalloc(sizeof(*ioas_dev), GFP_KERNEL);
	if (!ioas_dev) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/*
	 * Each ioas is backed by an iommu domain, which is allocated
	 * when the ioas is attached for the first time and then shared
	 * by following devices.
	 */
	if (xa_empty(&ioas->device)) {
		struct iommu_domain *d;

		d = iommu_domain_alloc(idev->dev->bus);
		if (!d) {
			ret = -ENOMEM;
			goto out_free;
		}
		ioas->domain = d;
	}
	domain = ioas->domain;

	/* Install the I/O page table to the iommu for this device */
	ret = iommu_attach_device(domain, idev->dev);
	if (ret)
		goto out_domain;

	ret = vfio_iommu_add_device(ioas->vfio_iommu, idev->dev, domain);
	if (ret)
		goto out_detach;

	ioas_dev->idev = idev;

	ret = xa_alloc(&ioas->device, &id, ioas_dev,
		       XA_LIMIT(idev->devid, idev->devid), GFP_KERNEL);
	if (ret)
		goto out_remove;

	up_write(&ioas->device_lock);

	return 0;
out_remove:
	vfio_iommu_remove_device(ioas->vfio_iommu, idev->dev);
out_detach:
	iommu_detach_device(domain, idev->dev);
out_domain:
	ioas_free_domain_if_empty(ioas);
out_free:
	kfree(ioas_dev);
out_unlock:
	up_write(&ioas->device_lock);
	ioas_put(ioas);

	return ret;
}
EXPORT_SYMBOL_GPL(iommufd_device_attach_ioas);

/**
 * iommufd_device_detach_ioas - Detach an ioas from a device.
 * @idev: [in] Pointer to struct iommufd_device.
 * @ioas: [in] ioas points to an I/O address space.
 *
 */
void iommufd_device_detach_ioas(struct iommufd_device *idev, u32 ioas_id)
{
	struct iommufd_ioas *ioas;
	struct ioas_device_info *ioas_dev;

	ioas = ioasid_get_ioas(idev->ictx, ioas_id);
	if (!ioas)
		return;

	down_write(&ioas->device_lock);

	ioas_dev = xa_erase(&ioas->device, idev->devid);
	if (!ioas_dev) {
		up_write(&ioas->device_lock);
		goto out;
	}
	vfio_iommu_remove_device(ioas->vfio_iommu, idev->dev);
	iommu_detach_device(ioas->domain, idev->dev);
	ioas_free_domain_if_empty(ioas);
	kfree(ioas_dev);

	up_write(&ioas->device_lock);

	/* release the reference acquired at the start of this function */
	ioas_put(ioas);
out:
	ioas_put(ioas);
}
EXPORT_SYMBOL_GPL(iommufd_device_detach_ioas);

/**
 * iommufd_bind_device - Bind a physical device marked by a device
 *			 cookie to an iommu fd.
 * @fd:		[in] iommufd file descriptor.
 * @dev:	[in] Pointer to a physical device struct.
 * @dev_cookie:	[in] A cookie to mark the device in /dev/iommu uAPI.
 *
 * A successful bind establishes a security context for the device
 * and returns struct iommufd_device pointer. Otherwise returns
 * error pointer.
 *
 */
struct iommufd_device *iommufd_bind_device(int fd, struct device *dev,
					   u64 dev_cookie)
{
	struct file *filp;
	struct iommufd_ctx *ictx;
	struct iommufd_device *idev;
	int ret;

	filp = iommufd_fget(fd);
	if (!filp)
		return ERR_PTR(-EINVAL);

	ictx = filp->private_data;

	idev = kzalloc(sizeof(*idev), GFP_KERNEL);
	if (!idev) {
		ret = -ENOMEM;
		goto out_file_put;
	}

	/* Set the DMA owner to be userspace */
	ret = iommu_device_set_dma_owner(dev, DMA_OWNER_USER, filp);
	if (ret)
		goto out_free;

	idev->ictx = ictx;
	idev->dev = dev;
	idev->dev_cookie = dev_cookie;

	ret = xa_alloc(&ictx->device_xa, &idev->devid, idev,
		       xa_limit_32b, GFP_KERNEL);
	if (ret)
		goto out_release_owner;

	return idev;

out_release_owner:
	iommu_device_release_dma_owner(dev, DMA_OWNER_USER);
out_free:
	kfree(idev);
out_file_put:
	fput(filp);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(iommufd_bind_device);

/**
 * iommufd_unbind_device - Unbind a physical device from iommufd
 *
 * @idev: [in] Pointer to the internal iommufd_device struct.
 *
 */
void iommufd_unbind_device(struct iommufd_device *idev)
{
	struct iommufd_ctx *ictx = idev->ictx;

	xa_erase(&ictx->device_xa, idev->devid);
	/* Release DMA owner */
	iommu_device_release_dma_owner(idev->dev, DMA_OWNER_USER);
	kfree(idev);
	fput(ictx->filp);
}
EXPORT_SYMBOL_GPL(iommufd_unbind_device);

u32 iommufd_device_get_id(struct iommufd_device *idev)
{
	return idev->devid;
}
EXPORT_SYMBOL_GPL(iommufd_device_get_id);

static int __init iommufd_init(void)
{
	int ret;

	ret = misc_register(&iommu_misc_dev);
	if (ret) {
		pr_err("failed to register misc device\n");
		return ret;
	}

	return 0;
}

static void __exit iommufd_exit(void)
{
	misc_deregister(&iommu_misc_dev);
}

module_init(iommufd_init);
module_exit(iommufd_exit);

MODULE_AUTHOR("Liu Yi L <yi.l.liu@intel.com>");
MODULE_DESCRIPTION("I/O Address Space Management for passthrough devices");
MODULE_LICENSE("GPL v2");
