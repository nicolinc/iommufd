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

static int iommufd_fops_open(struct inode *inode, struct file *filp)
{
	struct iommufd_ctx *ictx;
	int ret = 0;

	ictx = kzalloc(sizeof(*ictx), GFP_KERNEL);
	if (!ictx)
		return -ENOMEM;

	xa_init_flags(&ictx->device_xa, XA_FLAGS_ALLOC1);
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

static int iommufd_fops_release(struct inode *inode, struct file *filp)
{
	struct iommufd_ctx *ictx = filp->private_data;

	WARN_ON(!xa_empty(&ictx->device_xa));
	kfree(ictx);

	return 0;
}

static long iommufd_fops_unl_ioctl(struct file *filp,
				   unsigned int cmd, unsigned long arg)
{
	long ret = -EINVAL;

	switch (cmd) {
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
