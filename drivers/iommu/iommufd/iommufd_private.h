// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Intel Corporation
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __IOMMUFD_PRIVATE_H
#define __IOMMUFD_PRIVATE_H

#include <linux/rwsem.h>
#include <linux/xarray.h>
#include <linux/refcount.h>
#include <linux/uaccess.h>

#include <uapi/linux/iommufd.h>

struct iommu_domain;
struct iommu_group;

/*
 * The IOVA to PFN map. The mapper auotmatically copies the PFNs into multiple
 * domains and permits sharing of PFNs between io_pagetable instances. This
 * supports both a design where IOAS's are 1:1 with a domain (eg because the
 * domain is HW customized), or where the IOAS is 1:N with multiple generic
 * domains.  The io_pagetable holds an interval tree of iopt_areas which point
 * to shared iopt_pages which hold the pfns mapped to the page table.
 */
struct io_pagetable {
	struct rw_semaphore rwsem;
	struct xarray domains;
	unsigned int next_domain_id;
	struct rb_root_cached area_itree;
	struct rb_root_cached reserved_iova_itree;
	unsigned long iova_alignment;
};

int iopt_init_table(struct io_pagetable *iopt);
void iopt_destroy_table(struct io_pagetable *iopt);
int iopt_alloc_iova(struct io_pagetable *iopt, unsigned long *iova,
		    unsigned long uptr, unsigned long length);
struct iopt_pages *iopt_get_pages(struct io_pagetable *iopt, unsigned long iova,
				  unsigned long length);
int iopt_map_user_pages(struct io_pagetable *iopt, unsigned long iova,
			void __user *uptr, unsigned long length, int iommu_prot);
int iopt_copy_iova(struct io_pagetable *dst, struct iopt_pages *pages,
		   unsigned long dst_iova, unsigned long length, int iommu_prot);
int iopt_unmap_iova(struct io_pagetable *iopt, unsigned long iova,
		    unsigned long length);
int iopt_unmap_all(struct io_pagetable *iopt);

int iopt_access_pages(struct io_pagetable *iopt, unsigned long iova,
		      size_t npages, struct page **out_pages, bool write);
void iopt_unaccess_pages(struct io_pagetable *iopt, unsigned long iova,
			 size_t npages);
int iopt_table_add_domain(struct io_pagetable *iopt,
			  struct iommu_domain *domain);
void iopt_table_remove_domain(struct io_pagetable *iopt,
			      struct iommu_domain *domain);
int iopt_table_enforce_group_iova(struct io_pagetable *iopt,
				  struct iommu_group *group);
int iopt_reserve_iova(struct io_pagetable *iopt, unsigned long start,
		      unsigned long last, void *owner);
void iopt_remove_reserved_iova(struct io_pagetable *iopt, void *owner);

struct iommufd_ctx {
	struct file *filp;
	struct xarray objects;

	struct iommufd_ioas_pagetable *vfio_ioaspt;
	int vfio_fd;
};

struct iommufd_ctx *iommufd_fget(int fd);

struct iommufd_ucmd
{
	struct iommufd_ctx *ictx;
	void __user *ubuffer;
	u32 user_size;
	void *cmd;
	struct iommufd_object *new_object;
};

int iommufd_vfio_ioctl(struct iommufd_ctx *ictx, unsigned int cmd,
		       unsigned long arg);

/* Copy the filled in cmd struct back to userspace. */
static inline int iommufd_ucmd_respond(struct iommufd_ucmd *ucmd,
				       size_t cmd_len)
{
	if (copy_to_user(ucmd->ubuffer, ucmd->cmd,
			 min_t(size_t, ucmd->user_size, cmd_len)))
		return -EFAULT;
	return 0;
}

/*
 * The objects for an acyclic graph through the users refcount. This enum must
 * be sorted by type depth first so that destruction completes lower objects and
 * releases the users refcount before reaching higher objects in the graph.
 */
enum iommufd_object_type {
	IOMMUFD_OBJ_NONE,
	IOMMUFD_OBJ_ANY = IOMMUFD_OBJ_NONE,
	IOMMUFD_OBJ_DEVICE,
#ifdef CONFIG_IOMMUFD_TEST
	IOMMUFD_OBJ_SELFTEST,
#endif
	IOMMUFD_OBJ_HW_PAGETABLE,
	IOMMUFD_OBJ_IOAS_PAGETABLE,
	IOMMUFD_OBJ_MAX,
};

/* Base struct for all objects with a userspace ID handle. */
struct iommufd_object
{
	struct rw_semaphore destroy_rwsem;
	refcount_t users;
	enum iommufd_object_type type;
	unsigned int id;
};

static inline bool lock_obj(struct iommufd_object *obj)
{
	if (!down_read_trylock(&obj->destroy_rwsem))
		return false;
	if (!refcount_inc_not_zero(&obj->users)) {
		up_read(&obj->destroy_rwsem);
		return false;
	}
	return true;
}

struct iommufd_object *iommufd_get_object(struct iommufd_ctx *ictx, u32 id,
					   enum iommufd_object_type type);
static inline void iommufd_put_object(struct iommufd_object *obj)
{
	refcount_dec(&obj->users);
	up_read(&obj->destroy_rwsem);
}
static inline void iommufd_put_object_keep_user(struct iommufd_object *obj)
{
	up_read(&obj->destroy_rwsem);
}
void iommufd_object_finalize(struct iommufd_ctx *ictx,
			     struct iommufd_object *obj);
void iommufd_object_abort(struct iommufd_ctx *ictx, struct iommufd_object *obj);
bool iommufd_object_destroy_user(struct iommufd_ctx *ictx,
				 struct iommufd_object *obj);
struct iommufd_object *_iommufd_object_alloc(struct iommufd_ctx *ictx,
					     size_t size,
					     enum iommufd_object_type type);

#define iommufd_object_alloc(ictx, ptr, type)                                  \
	container_of(_iommufd_object_alloc(                                    \
			     ictx,                                             \
			     sizeof(*(ptr)) + BUILD_BUG_ON_ZERO(               \
						      offsetof(typeof(*(ptr)), \
							       obj) != 0),     \
			     type),                                            \
		     typeof(*(ptr)), obj)

/*
 * Allocate a new object inside an ioctl. The obj pointer becomes owned by the
 * ucmd. The allocation can be aborted by returning an error code from the
 * handler, or completed by returning success. There is no paired error unwind
 * function for this in the handler.
 */
#define iommufd_object_alloc_ucmd(ucmd, ptr, type)                             \
	({                                                                     \
		typeof(ptr) __tmp =                                            \
			iommufd_object_alloc((ucmd)->ictx, ptr, type);         \
		(ucmd)->new_object = &__tmp->obj;                              \
		__tmp;                                                         \
	})

/*
 * The IO Address Space (IOAS) pagetable is a virtual page table backed by the
 * io_pagetable object. It is a user controlled mapping of IOVA -> PFNs. The
 * mapping is copied into all of the associated domains and SW users.
 */
struct iommufd_ioas_pagetable {
	struct iommufd_object obj;
	struct io_pagetable iopt;
	struct list_head auto_domains;
};

static inline struct iommufd_ioas_pagetable *
get_ioas_pagetable(struct iommufd_ucmd *ucmd, u32 id)
{
	return container_of(iommufd_get_object(ucmd->ictx, id,
					       IOMMUFD_OBJ_IOAS_PAGETABLE),
			    struct iommufd_ioas_pagetable, obj);
}

struct iommufd_ioas_pagetable *
__iommufd_ioas_pagetable_alloc(struct iommufd_ctx *ictx);
int iommufd_ioas_pagetable_alloc(struct iommufd_ucmd *ucmd);
void iommufd_ioas_pagetable_destroy(struct iommufd_object *obj);
int iommufd_ioas_pagetable_iova_ranges(struct iommufd_ucmd *ucmd);
int iommufd_ioas_pagetable_map(struct iommufd_ucmd *ucmd);
int iommufd_ioas_pagetable_copy(struct iommufd_ucmd *ucmd);
int iommufd_ioas_pagetable_unmap(struct iommufd_ucmd *ucmd);

int __iommufd_ioas_pagetable_map(struct iommufd_ioas_pagetable *ioaspt,
				 struct iommu_ioas_pagetable_map *cmd);

/*
 * A HW pagetable is called an iommu_domain inside the kernel. This user object
 * allows directly creating and inspecting the domains. Domains that have kernel
 * owned page tables will be associated with an iommufd_ioas_pagetable that
 * provides the IOVA to PFN map.
 */
struct iommufd_hw_pagetable {
	struct iommufd_object obj;
	struct iommufd_ioas_pagetable *ioaspt;
	struct iommu_domain *domain;
	/* Head at iommufd_ioas_pagetable::auto_domains */
	struct list_head auto_domains_item;
	struct mutex devices_lock;
	struct list_head devices;
	refcount_t domain_attaches;
};

struct iommufd_hw_pagetable *
iommufd_hw_pagetable_from_id(struct iommufd_ctx *ictx, u32 pt_id,
			     struct device *dev);
void iommufd_hw_pagetable_put(struct iommufd_ctx *ictx,
			      struct iommufd_hw_pagetable *hwpt);
void iommufd_hw_pagetable_destroy(struct iommufd_object *obj);

void iommufd_device_destroy(struct iommufd_object *obj);

int iommufd_test(struct iommufd_ucmd *ucmd);
void iommufd_selftest_destroy(struct iommufd_object *obj);

#endif
