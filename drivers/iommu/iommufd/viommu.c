// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */

#include <linux/iommufd.h>

#include "iommufd_private.h"

#define viommu_struct_alloc(name)                                              \
	struct iommufd_##name *_iommufd_##name##_alloc(size_t size)            \
	{                                                                      \
		struct iommufd_object *obj;                                    \
		if (WARN_ON(size < sizeof(struct iommufd_##name)))             \
			return NULL;                                           \
		obj = ___iommufd_object_alloc(size);                           \
		if (IS_ERR(obj))                                               \
			return NULL;                                           \
		return container_of(obj, struct iommufd_##name, obj);          \
	}

viommu_struct_alloc(viommu);
