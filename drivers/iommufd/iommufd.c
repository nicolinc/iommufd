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

static void ioas_put(struct iommufd_ioas *ioas)
{
	struct iommufd_ctx *ictx = ioas->ictx;
	u32 ioas_id = ioas->ioas_id;

	if (!refcount_dec_and_test(&ioas->refs))
		return;

	xa_erase(&ictx->ioas_xa, ioas_id);
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

	refcount_set(&ioas->refs, 1);

	ret = xa_alloc(&ictx->ioas_xa, &ioas->ioas_id, ioas,
		       xa_limit_32b, GFP_KERNEL);
	if (ret)
		kfree(ioas);

	if (copy_to_user((void __user *)arg + minsz,
			 &ioas->ioas_id, sizeof(ioas->ioas_id))) {
		xa_erase(&ictx->ioas_xa, ioas->ioas_id);
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

	minsz = offsetofend(struct iommu_device_info, pgsize_bitmap);

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz || info.devid == IOMMUFD_INVALID_DEVID)
		return -EINVAL;

	info.flags = 0;

	idev = xa_load(&ictx->device_xa, info.devid);
	if (!idev)
		return -EINVAL;

	iommu_device_build_info(idev->dev, &info);

	return copy_to_user((void __user *)arg, &info, minsz) ? -EFAULT : 0;
}

static long iommufd_fops_unl_ioctl(struct file *filp,
				   unsigned int cmd, unsigned long arg)
{
	struct iommufd_ctx *ictx = filp->private_data;
	long ret = -EINVAL;

	switch (cmd) {
	case IOMMU_DEVICE_GET_INFO:
		ret = iommufd_get_device_info(ictx, arg);
		break;
	case IOMMU_IOAS_ALLOC:
		ret = iommufd_ioas_alloc(ictx, arg);
		break;
	case IOMMU_IOAS_FREE:
		ret = iommufd_ioas_free(ictx, arg);
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
