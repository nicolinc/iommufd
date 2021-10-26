/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IOMMUFD API definition
 *
 * Copyright (C) 2021 Intel Corporation
 *
 * Author: Liu Yi L <yi.l.liu@intel.com>
 */
#ifndef __LINUX_IOMMUFD_H
#define __LINUX_IOMMUFD_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/device.h>

struct iommufd_device;

#define IOMMUFD_INVALID_DEVID	0

#if IS_ENABLED(CONFIG_IOMMUFD)
struct iommufd_device *
iommufd_bind_device(int fd, struct device *dev, u64 dev_cookie);
void iommufd_unbind_device(struct iommufd_device *idev);
u32 iommufd_device_get_id(struct iommufd_device *idev);

#else /* !CONFIG_IOMMUFD */
static inline struct iommufd_device *
iommufd_bind_device(int fd, struct device *dev, u64 dev_cookie)
{
	return ERR_PTR(-ENODEV);
}

static inline void iommufd_unbind_device(struct iommufd_device *idev)
{
}

static inline u32 iommufd_device_get_id(struct iommufd_device *idev)
{
	return IOMMUFD_INVALID_DEVID;
}
#endif /* CONFIG_IOMMUFD */
#endif /* __LINUX_IOMMUFD_H */
