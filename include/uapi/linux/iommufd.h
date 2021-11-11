/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES.
 */
#ifndef _UAPI_IOMMUFD_H
#define _UAPI_IOMMUFD_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define IOMMUFD_TYPE (';')

enum {
	IOMMUFD_CMD_BASE = 0x80,
	IOMMUFD_CMD_DESTROY = IOMMUFD_CMD_BASE,
	IOMMUFD_CMD_IOAS_PAGETABLE_ALLOC,
	IOMMUFD_CMD_IOAS_PAGETABLE_IOVA_RANGES,
	IOMMUFD_CMD_IOAS_PAGETABLE_MAP,
	IOMMUFD_CMD_IOAS_PAGETABLE_COPY,
	IOMMUFD_CMD_IOAS_PAGETABLE_UNMAP,
	IOMMUFD_CMD_VFIO_IOAS,
};

/*
 * Destroy any object. id is an ID returned from another command.
 */
struct iommu_destroy
{
	__u32 size;
	__u32 id;
};
#define IOMMU_DESTROY _IO(IOMMUFD_TYPE, IOMMUFD_CMD_DESTROY)

/*
 * Allocate an IO Address Space (IOAS) which holds an IO Virtual Address (IOVA)
 * to memory mapping.
 */
struct iommu_ioas_pagetable_alloc
{
	__u32 size;
	__u32 flags;
	__u32 out_ioas_id;
};
#define IOMMU_IOAS_PAGETABLE_ALLOC                                             \
	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_PAGETABLE_ALLOC)

/*
 * Query an IOAS for ranges of allowed IOVAs. Operation outside these ranges is
 * not allowed. out_num_iovas will be set to the total number of iovas
 * and the out_valid_iovas[] will be filled in as space permits.
 * size should include the allocted flex array.
 */
struct iommu_ioas_pagetable_iova_ranges
{
	__u32 size;
	__u32 ioas_id;
	__u32 out_num_iovas;
	__u32 __reserved;
	struct {
		__aligned_u64 start;
		__aligned_u64 last;
	} out_valid_iovas[];
};
#define IOMMU_IOAS_PAGETABLE_IOVA_RANGES                                       \
	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_PAGETABLE_IOVA_RANGES)

/*
 * Set an IOVA mapping from a user pointer. If FIXED_IOVA is specified then the
 * mapping will be established at iova, otherwise a suitable location will be
 * automatically selected and returned in iova.
 */
struct iommu_ioas_pagetable_map
{
	__u32 size;
#define IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA (1 << 0)
#define IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE (1 << 1)
#define IOMMU_IOAS_PAGETABLE_MAP_READABLE (1 << 1)
	__u32 flags;
	__u32 ioas_id;
	__u32 __reserved;
	__aligned_u64 user_va;
	__aligned_u64 length;
	__aligned_u64 iova;
};
#define IOMMU_IOAS_PAGETABLE_MAP                                               \
	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_PAGETABLE_MAP)

/*
 * Copy an already existing mapping from another IOAS. The src iova/length
 * must exactly match a range used with IOMMU_IOAS_PAGETABLE_MAP.
 */
struct iommu_ioas_pagetable_copy
{
	__u32 size;
	/* IOMMU_IOAS_PAGETABLE_MAP_* */
	__u32 flags;
	__u32 dst_ioas_id;
	__u32 src_ioas_id;
	__aligned_u64 length;
	__aligned_u64 dst_iova;
	__aligned_u64 src_iova;
};
#define IOMMU_IOAS_PAGETABLE_COPY                                               \
	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_PAGETABLE_COPY)

/*
 * Unmap an IOVA range. The iova/length must exactly match a range
 * used with IOMMU_IOAS_PAGETABLE_MAP, or be the values 0 & U64_MAX.
 * In the latter case all IOVAs will be unmaped.
 */
struct iommu_ioas_pagetable_unmap
{
	__u32 size;
	__u32 ioas_id;
	__aligned_u64 iova;
	__aligned_u64 length;
};
#define IOMMU_IOAS_PAGETABLE_UNMAP                                             \
	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_PAGETABLE_UNMAP)

/*
 * The VFIO compatability support uses a single ioas because VFIO APIs do not
 * support the ID field. Set or Get the IOAS that VFIO compatabilitiy will use.
 * If no IOAS is assigned then VFIO compatability will auto-create an IOAS when
 * needed and GET will return this ID. SET or CLEAR does not destroy the
 * auto-created IOAS.
 */
#define IOMMU_VFIO_IOAS_GET 0
#define IOMMU_VFIO_IOAS_SET 1
#define IOMMU_VFIO_IOAS_CLEAR 2
struct iommu_vfio_ioas {
	__u32 size;
	__u32 ioas_id;
	__u16 op;
	__u16 reserved;
};
#define IOMMU_VFIO_IOAS _IO(IOMMUFD_TYPE, IOMMUFD_CMD_VFIO_IOAS)

// FIXME: Below here is only an example:
enum {
	IOMMU_DRIVER_DATA_NONE = 0,
	IOMMU_DRIVER_DATA_INTEL_xxx,
	IOMMU_DRIVER_DATA_ARM_xxx,
};

struct iommu_hw_pt_alloc_arm_smmuv3_dd
{
	__u32 flags;
	__u32 type;
	union {
		struct {} type1;
		struct {} type2;
	};
};

struct iommu_hw_pagetable_alloc
{
	__u32 size;
	__u32 flags;
	__u32 ioas_id;
	__u32 out_hw_pt_id;
	__u32 nested_hw_pt_id;
	__u32 device_id;
	__u32 driver_data_type; // of IOMMU_DRIVER_DATA_*
	__u32 driver_data_len;
	__u32 __reserved;
	__aligned_u64 driver_data;
};

#define IOMMU_HW_PAGETABLE_ALLOC                                               \
	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_HW_PAGETABLE_ALLOC)

struct iommu_hw_device_info_intel_xxx
{
	__u32 intel_thing1;
	__u32 intel_thing2;
};

struct iommu_hw_device_info
{
	__u32 size;
	__u32 flags;
	__u32 device_id;
	__u32 drvier_data_type;
	__u32 driver_data_len;
	__u32 __reserved;
	__aligned_u64 driver_data;
	__u32 general_thing1;
	__u32 general_thing2;
	__u32 general_thing3;
};

#endif
