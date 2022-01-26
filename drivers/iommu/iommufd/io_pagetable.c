// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES.
 *
 * This is a datastructure intended to map IOVA's to PFNs. The PFNs can be
 * placed into an iommu_domain, or returned to the caller as a page list, for
 * emulated SW access.
 *
 * The datastructre is designed to be able to share chunks of PFNs between
 * different maps (to minimize the number of page pins required) and to be able
 * to store the pfns themselves inside the page table within an struct
 * iommu_domain. (avoid duplicate storage)
 *
 * It is a straightforward scheme, except for the transition from having an
 * iommu_domain hold the pfns to having the emulated domain hold the pfns. On
 * this edge the PFNs have to be moved between the iommu_domain and a xarray
 * that holds the PFNs.
 *
 * This is further complicated because the iommu_domain requires pinning ever
 * PFN, but the SW domain does not. So there are algorithms to selectively pin
 * based on emulated usages, again optimized to single pin.
 *
 * The design does not support splitting or hole punching in the allocations.
 * Each mapped in IOVA range is an object and must be manipulated as-is. This
 * matches the current VFIO semantic and significantly simplifies the design.
 */
#include <linux/lockdep.h>
#include <linux/iommu.h>
#include <linux/sched/mm.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/errno.h>

#include "io_pagetable.h"

static unsigned long iopt_iova_to_index(struct iopt_area *area,
					unsigned long iova)
{
	if (IS_ENABLED(CONFIG_IOMMUFD_TEST))
		WARN_ON(iova < iopt_area_iova(area) ||
			iova > iopt_area_last_iova(area));
	return (iova - (iopt_area_iova(area) & PAGE_MASK)) / PAGE_SIZE;
}

static struct iopt_area *iopt_area_find_exact(struct io_pagetable *iopt,
					      unsigned long iova,
					      unsigned long last_iova)
{
	struct iopt_area *area;

	area = iopt_area_iter_first(iopt, iova, last_iova);
	if (!area || area->node.start != iova || area->node.last != last_iova)
		return NULL;
	return area;
}

static struct iopt_pages *iopt_alloc_pages(void __user *uptr,
					   unsigned long iova,
					   unsigned long length, bool writable)
{
	struct iopt_pages *pages;

	/*
	 * The iommu API uses size_t as the length, and protect the DIV_ROUND_UP
	 * below from overflow
	 */
	if (length > SIZE_MAX - PAGE_SIZE)
		return ERR_PTR(-EINVAL);
	if ((iova % PAGE_SIZE) != (((uintptr_t)uptr) % PAGE_SIZE))
		return ERR_PTR(-EINVAL);

	pages = kzalloc(sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	kref_init(&pages->kref);
	xa_init(&pages->pinned_pfns);
	mutex_init(&pages->mutex);
	pages->source_mm = current->mm;
	mmgrab(pages->source_mm);
	pages->uptr = (void __user *)ALIGN_DOWN((uintptr_t)uptr, PAGE_SIZE);
	pages->npages = DIV_ROUND_UP(length + (uptr - pages->uptr), PAGE_SIZE);
	pages->users_itree = RB_ROOT_CACHED;
	pages->domains_itree = RB_ROOT_CACHED;
	pages->writable = writable;

	return pages;
}

static void iopt_release_pages(struct kref *kref)
{
	struct iopt_pages *pages = container_of(kref, struct iopt_pages, kref);

	WARN_ON(!RB_EMPTY_ROOT(&pages->users_itree.rb_root));
	WARN_ON(!RB_EMPTY_ROOT(&pages->domains_itree.rb_root));
	WARN_ON(pages->npinned);
	WARN_ON(!xa_empty(&pages->pinned_pfns));
	mmdrop(pages->source_mm);
	mutex_destroy(&pages->mutex);
	kfree(pages);
}

static void iopt_put_pages(struct iopt_pages *pages)
{
	kref_put(&pages->kref, iopt_release_pages);
}

static struct iopt_area *iopt_alloc_area(struct io_pagetable *iopt,
					 unsigned long iova,
					 unsigned long length,
					 struct iopt_pages *pages,
					 int iommu_prot)
{
	struct iopt_area *area;
	unsigned long iova_end;

	if ((iova & (iopt->iova_alignment - 1)) ||
	    (length & (iopt->iova_alignment - 1)) || !length)
		return ERR_PTR(-EINVAL);

	if (check_add_overflow(iova, length - 1, &iova_end))
		return ERR_PTR(-EOVERFLOW);

	/* Check that there is not already a mapping in the range */
	if (iopt_area_iter_first(iopt, iova, iova_end))
		return ERR_PTR(-EADDRINUSE);

	/* No reserved IOVA intersects the range */
	if (interval_tree_iter_first(&iopt->reserved_iova_itree, iova,
				     iova_end))
		return ERR_PTR(-ENOENT);

	if ((iommu_prot & IOMMU_WRITE) && !pages->writable)
		return ERR_PTR(-EPERM);

	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (!area)
		return ERR_PTR(-ENOMEM);
	area->node.start = iova;
	area->node.last = iova_end;
	area->pages_node.start = 0;
	area->pages_node.last = pages->npages - 1;
	area->iopt = iopt;
	area->iommu_prot = iommu_prot;
	/* Move the reference in from the caller */
	area->pages = pages;
	return area;
}

static void iopt_free_area(struct iopt_area *area)
{
	iopt_put_pages(area->pages);
	kfree(area);
}

static bool __alloc_iova_check_hole(struct interval_tree_span_iter *span,
				    unsigned long length,
				    unsigned long iova_alignment,
				    unsigned long iova_bits)
{
	if (!span->is_hole || span->last_hole - span->start_hole < length - 1)
		return false;

	span->start_hole = ALIGN(span->start_hole, iova_alignment) | iova_bits;
	if (span->start_hole > span->last_hole ||
	    span->last_hole - span->start_hole < length - 1)
		return false;
	return true;
}

/**
 * iopt_alloc_iova - Find an available range of iova
 *
 * Automatically find a block of IOVA that is not being used and not reserved.
 * Does not return a 0 IOVA even if it is valid.
 */
int iopt_alloc_iova(struct io_pagetable *iopt, unsigned long *iova,
		    unsigned long uptr, unsigned long length)
{
	struct interval_tree_span_iter reserved_span;
	unsigned long iova_bits = uptr % PAGE_SIZE;
	struct interval_tree_span_iter area_span;
	unsigned long iova_alignment;

	lockdep_assert_held(&iopt->rwsem);

	if (length == 0 || length >= ULONG_MAX / 2)
		return -EINVAL;

	/*
	 * Keep alignment present in the uptr when building the IOVA, this
	 * increases the chance we can map a THP.
	 */
	if (!uptr)
		iova_alignment = roundup_pow_of_two(length);
	else
		iova_alignment =
			min_t(unsigned long, roundup_pow_of_two(length),
			      1UL << __ffs64(uptr));

	if (iova_alignment < iopt->iova_alignment)
		return -EINVAL;
	for (interval_tree_span_iter_first(&area_span, &iopt->area_itree,
					   PAGE_SIZE, ULONG_MAX - PAGE_SIZE);
	     !interval_tree_span_iter_done(&area_span);
	     interval_tree_span_iter_next(&area_span)) {
		if (!__alloc_iova_check_hole(&area_span, length, iova_alignment,
					     iova_bits))
			continue;

		for (interval_tree_span_iter_first(
			     &reserved_span, &iopt->reserved_iova_itree,
			     area_span.start_hole, area_span.last_hole);
		     !interval_tree_span_iter_done(&reserved_span);
		     interval_tree_span_iter_next(&reserved_span)) {
			if (!__alloc_iova_check_hole(&reserved_span, length,
						     iova_alignment, iova_bits))
				continue;

			*iova = reserved_span.start_hole;
			return 0;
		}
	}
	return -ENOSPC;
}

/**
 * iopt_map_user_pages - Assign a user va to an iova in the io page table
 *
 * iova, uptr, and length must have a PAGE_SIZE alignment. For domain backed
 * page tables this will pin the pages and load them into the domain at iova.
 * For non-domain page tables this will only setup a lazy reference and the
 * caller must use iopt_access_pages() to touch them.
 *
 * iopt_unmap_iova() must be called to undo this before the io_pagetable can be
 * destroyed.
 */
int iopt_map_user_pages(struct io_pagetable *iopt, unsigned long iova,
			void __user *uptr, unsigned long length, int iommu_prot)
{
	struct iopt_pages *pages;
	struct iopt_area *area;
	int rc;

	lockdep_assert_held_write(&iopt->rwsem);

	pages = iopt_alloc_pages(uptr, iova, length, iommu_prot & IOMMU_WRITE);
	if (IS_ERR(pages)) {
		return PTR_ERR(pages);
	}

	area = iopt_alloc_area(iopt, iova, length, pages, iommu_prot);
	if (IS_ERR(area)) {
		iopt_put_pages(pages);
		return PTR_ERR(area);
	}

	rc = iopt_area_fill_domains(area);
	if (rc)
		goto out_free_area;
	interval_tree_insert(&area->node, &area->iopt->area_itree);
	return 0;

out_free_area:
	iopt_free_area(area);
	return rc;
}

struct iopt_pages *iopt_get_pages(struct io_pagetable *iopt, unsigned long iova,
				  unsigned long length)
{
	unsigned long iova_end;
	struct iopt_pages *pages;
	struct iopt_area *area;

	if (check_add_overflow(iova, length - 1, &iova_end))
		return ERR_PTR(-EOVERFLOW);

	down_read(&iopt->rwsem);
	area = iopt_area_find_exact(iopt, iova, iova_end);
	if (!area) {
		up_read(&iopt->rwsem);
		return ERR_PTR(-ENOENT);
	}
	pages = area->pages;
	kref_get(&pages->kref);
	up_read(&iopt->rwsem);

	return pages;
}

int iopt_copy_iova(struct io_pagetable *dst, struct iopt_pages *pages,
		   unsigned long dst_iova, unsigned long length, int iommu_prot)
{
	struct iopt_area *area;
	int rc;

	lockdep_assert_held(&dst->rwsem);

	if ((iommu_prot & IOMMU_WRITE) && !pages->writable) {
		iopt_put_pages(pages);
		return -EPERM;
	}

	area = iopt_alloc_area(dst, dst_iova, length, pages, iommu_prot);
	if (IS_ERR(area)) {
		iopt_put_pages(pages);
		return PTR_ERR(area);
	}

	rc = iopt_area_fill_domains(area);
	if (rc)
		goto out_free_area;
	interval_tree_insert(&area->node, &area->iopt->area_itree);
	return 0;

out_free_area:
	iopt_free_area(area);
	return rc;
}

static int __iopt_unmap_iova(struct io_pagetable *iopt, struct iopt_area *area)
{
	/* Drivers have to unpin on notification. */
	if (WARN_ON(atomic_read(&area->num_users)))
		return -EBUSY;

	interval_tree_remove(&area->node, &iopt->area_itree);
	iopt_area_unfill_domains(area);
	WARN_ON(atomic_read(&area->num_users));
	iopt_free_area(area);
	return 0;
}

/**
 * iopt_unmap_iova - Remove a range of iova
 *
 * The requested range must exactly match an existing range.
 * Splitting/truncating IOVA mappings is not allowed.
 */
int iopt_unmap_iova(struct io_pagetable *iopt, unsigned long iova,
		    unsigned long length)
{
	struct iopt_area *area;
	unsigned long iova_end;
	int rc;

	if (!length)
		return -EINVAL;

	if (check_add_overflow(iova, length - 1, &iova_end))
		return -EOVERFLOW;

	down_write(&iopt->rwsem);
	area = iopt_area_find_exact(iopt, iova, iova_end);
	if (!area) {
		rc = -ENOENT;
		goto out_unlock;
	}

	rc = __iopt_unmap_iova(iopt, area);
out_unlock:
	up_write(&iopt->rwsem);
	return rc;
}

int iopt_unmap_all(struct io_pagetable *iopt)
{
	struct iopt_area *area;
	int rc;

	down_write(&iopt->rwsem);
	while ((area = iopt_area_iter_first(iopt, 0, ULONG_MAX))) {
		rc = __iopt_unmap_iova(iopt, area);
		if (rc)
			goto out_unlock;
	}
	rc = 0;

out_unlock:
	up_write(&iopt->rwsem);
	return rc;
}

static struct iopt_pages_user *
iopt_pages_get_exact_user(struct iopt_pages *pages, unsigned long index,
			  unsigned long last)
{
	struct interval_tree_node *node;

	lockdep_assert_held(&pages->mutex);

	/* There can be overlapping ranges in this interval tree */
	for (node = interval_tree_iter_first(&pages->users_itree, index, last);
	     node; node = interval_tree_iter_next(node, index, last))
		if (node->start == index && node->last == last)
			return container_of(node, struct iopt_pages_user, node);
	return NULL;
}

static int iopt_pages_add_user(struct iopt_pages *pages, unsigned long index,
			       unsigned long last, struct page **out_pages,
			       bool write)
{
	struct iopt_pages_user *user;
	int rc;

	if (pages->writable != write)
		return -EPERM;

	mutex_lock(&pages->mutex);
	user = iopt_pages_get_exact_user(pages, index, last);
	if (user) {
		refcount_inc(&user->refcount);
		mutex_unlock(&pages->mutex);
		iopt_pages_fill_from_xarray(pages, index, last, out_pages);
		return 0;
	}

	user = kzalloc(sizeof(*user), GFP_KERNEL);
	if (!user) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	rc = iopt_pages_fill_xarray(pages, index, last, out_pages);
	if (rc)
		goto out_free;

	user->node.start = index;
	user->node.last = last;
	refcount_set(&user->refcount, 1);
	interval_tree_insert(&user->node, &pages->users_itree);
	mutex_unlock(&pages->mutex);
	return 0;

out_free:
	kfree(user);
out_unlock:
	mutex_unlock(&pages->mutex);
	return rc;
}

static void iopt_pages_remove_user(struct iopt_pages *pages,
				   unsigned long index, unsigned long last)
{
	struct iopt_pages_user *user;

	mutex_lock(&pages->mutex);
	user = iopt_pages_get_exact_user(pages, index, last);
	if (WARN_ON(!user))
		goto out_unlock;

	if (!refcount_dec_and_test(&user->refcount))
		goto out_unlock;

	interval_tree_remove(&user->node, &pages->users_itree);
	iopt_pages_unfill_xarray(pages, index, last);
	kfree(user);
out_unlock:
	mutex_unlock(&pages->mutex);
}

/**
* iopt_access_pages - Return a list of pages under the iova
*
* Reads @npages starting at iova and returns the struct page * pointers. These
* can be kmap'd by the caller for CPU access.
*
* The caller must perform iopt_unaccess_pages() when done to balance this.
*
* iova can be unaligned from PAGE_SIZE. The first returned byte starts at
* page_to_phys(out_pages[0]) + (iova % PAGE_SIZE). The caller promises not
* to touch memory outside the requested iova slice.
*
* FIXME: callers that need a DMA mapping via a sgl should create another
* interface to build the SGL efficiently
*/
int iopt_access_pages(struct io_pagetable *iopt, unsigned long iova,
		      size_t length, struct page **out_pages, bool write)
{
	unsigned long cur_iova = iova;
	unsigned long last_iova;
	struct iopt_area *area;
	int rc;

	if (!length)
		return -EINVAL;
	if (check_add_overflow(iova, length - 1, &last_iova))
		return -EOVERFLOW;

	down_read(&iopt->rwsem);
	for (area = iopt_area_iter_first(iopt, iova, last_iova); area;
	     area = iopt_area_iter_next(area, iova, last_iova)) {
		unsigned long last = min(last_iova, iopt_area_last_iova(area));
		unsigned long last_index;
		unsigned long index;

		/* Need contiguous areas in the access */
		if (iopt_area_iova(area) < cur_iova) {
			rc = -EINVAL;
			goto out_remove;
		}

		index = iopt_iova_to_index(area, cur_iova);
		last_index = iopt_iova_to_index(area, last);
		rc = iopt_pages_add_user(area->pages, index, last_index,
					 out_pages, write);
		if (rc)
			goto out_remove;
		if (last == last_iova)
			break;
		/*
		 * Can't cross areas that are not aligned to the system page
		 * size with this API.
		 */
		if (cur_iova % PAGE_SIZE) {
			rc = -EINVAL;
			goto out_remove;
		}
		cur_iova = last + 1;
		out_pages += last_index - index;
		atomic_inc(&area->num_users);
	}

	up_read(&iopt->rwsem);
	return 0;

out_remove:
	if (cur_iova != iova)
		iopt_unaccess_pages(iopt, iova, cur_iova - iova);
	return rc;
}

/**
 * iopt_unaccess_pages - Undo iopt_access_pages
 *
 * Return the struct page's. The caller must stop accessing them before calling
 * this.
 */
void iopt_unaccess_pages(struct io_pagetable *iopt, unsigned long iova,
			 size_t length)
{
	unsigned long cur_iova = iova;
	unsigned long last_iova;
	struct iopt_area *area;

	if (WARN_ON(!length) ||
	    WARN_ON(check_add_overflow(iova, length - 1, &last_iova)))
		return;

	down_read(&iopt->rwsem);
	for (area = iopt_area_iter_first(iopt, iova, last_iova); area;
	     area = iopt_area_iter_next(area, iova, last_iova)) {
		unsigned long last = min(last_iova, iopt_area_last_iova(area));
		int num_users;

		iopt_pages_remove_user(area->pages,
				       iopt_iova_to_index(area, cur_iova),
				       iopt_iova_to_index(area, last));
		if (last == last_iova)
			break;
		cur_iova = last + 1;
		num_users = atomic_dec_return(&area->num_users);
		WARN_ON(num_users < 0);
	}
	up_read(&iopt->rwsem);
}

struct iopt_reserved_iova {
	struct interval_tree_node node;
	void *owner;
};

int iopt_reserve_iova(struct io_pagetable *iopt, unsigned long start,
		      unsigned long last, void *owner)
{
	struct iopt_reserved_iova *reserved;

	reserved = kzalloc(sizeof(*reserved), GFP_KERNEL);
	if (!reserved)
		return -ENOMEM;
	reserved->node.start = start;
	reserved->node.last = last;
	reserved->owner = owner;
	interval_tree_insert(&reserved->node, &iopt->reserved_iova_itree);
	return 0;
}

void iopt_remove_reserved_iova(struct io_pagetable *iopt, void *owner)
{

	struct interval_tree_node *node;

	for (node = interval_tree_iter_first(&iopt->reserved_iova_itree, 0,
					     ULONG_MAX);
	     node;) {
		struct iopt_reserved_iova *reserved =
			container_of(node, struct iopt_reserved_iova, node);

		node = interval_tree_iter_next(node, 0, ULONG_MAX);

		if (reserved->owner == owner) {
			interval_tree_remove(&reserved->node,
					     &iopt->reserved_iova_itree);
			kfree(reserved);
		}
	}
}

int iopt_init_table(struct io_pagetable *iopt)
{
	init_rwsem(&iopt->rwsem);
	iopt->area_itree = RB_ROOT_CACHED;
	iopt->reserved_iova_itree = RB_ROOT_CACHED;
	xa_init(&iopt->domains);

	/*
	 * iopt's start as SW tables that can use the entire size_t IOVA space
	 * due to the use of size_t in the APIs. They have no alignment
	 * restriction.
	 */
	iopt->iova_alignment = 1;

	return 0;
}

void iopt_destroy_table(struct io_pagetable *iopt)
{
	if (IS_ENABLED(CONFIG_IOMMUFD_TEST))
		iopt_remove_reserved_iova(iopt, NULL);
	WARN_ON(!RB_EMPTY_ROOT(&iopt->reserved_iova_itree.rb_root));
	WARN_ON(!xa_empty(&iopt->domains));
	WARN_ON(!RB_EMPTY_ROOT(&iopt->area_itree.rb_root));
}

/* All existing area's conform to an increased page size */
static int iopt_check_iova_alignment(struct io_pagetable *iopt,
				     unsigned long new_iova_alignment)
{
	struct iopt_area *area;

	lockdep_assert_held(&iopt->rwsem);

	for (area = iopt_area_iter_first(iopt, 0, ULONG_MAX); area;
	     area = iopt_area_iter_next(area, 0, ULONG_MAX))
		if ((iopt_area_iova(area) % new_iova_alignment) ||
		    (iopt_area_length(area) % new_iova_alignment))
			return -EADDRINUSE;
	return 0;
}

int iopt_table_add_domain(struct io_pagetable *iopt,
			  struct iommu_domain *domain)
{
	const struct iommu_domain_geometry *geometry = &domain->geometry;
	struct iommu_domain *iter_domain;
	unsigned int new_iova_alignment;
	unsigned long index;
	int rc;

	lockdep_assert_held_write(&iopt->rwsem);

	xa_for_each (&iopt->domains, index, iter_domain)
		if (WARN_ON(iter_domain == domain))
			return -EEXIST;

	/*
	 * The io page size drives the iova_alignment. Internally the iopt_pages
	 * works in PAGE_SIZE units and we adjust when mapping sub-PAGE_SIZE
	 * objects into the iommu_domina.
	 *
	 * A iommu_domain must always be able to accept PAGE_SIZE to be
	 * compatible as we can't guarentee higher contiguity.
	 */
	new_iova_alignment =
		max_t(unsigned long, 1UL << __ffs(domain->pgsize_bitmap),
		      iopt->iova_alignment);
	if (new_iova_alignment > PAGE_SIZE)
		return -EINVAL;
	if (new_iova_alignment != iopt->iova_alignment) {
		rc = iopt_check_iova_alignment(iopt, new_iova_alignment);
		if (rc)
			return rc;
	}

	/* No area exists that is outside the allowed domain aperture */
	if (geometry->aperture_start != 0) {
		if (iopt_area_iter_first(iopt, 0, geometry->aperture_start - 1))
			return -EADDRINUSE;
		rc = iopt_reserve_iova(iopt, 0, geometry->aperture_start - 1,
				       domain);
		if (rc)
			goto out_reserved;
	}
	if (0 < geometry->aperture_end && geometry->aperture_end < ULONG_MAX) {
		if (iopt_area_iter_first(iopt, geometry->aperture_end + 1,
					 ULONG_MAX))
			return -EADDRINUSE;
		rc = iopt_reserve_iova(iopt, geometry->aperture_end + 1,
				       ULONG_MAX, domain);
		if (rc)
			goto out_reserved;
	}

	rc = xa_reserve(&iopt->domains, iopt->next_domain_id, GFP_KERNEL);
	if (rc)
		goto out_reserved;

	rc = iopt_fill_domain(iopt, domain);
	if (rc)
		goto out_release;

	iopt->iova_alignment = new_iova_alignment;
	xa_store(&iopt->domains, iopt->next_domain_id, domain,
			     GFP_KERNEL);
	iopt->next_domain_id++;
	return 0;
out_release:
	xa_release(&iopt->domains, iopt->next_domain_id);
out_reserved:
	iopt_remove_reserved_iova(iopt, domain);
	return rc;
}

void iopt_table_remove_domain(struct io_pagetable *iopt,
			      struct iommu_domain *domain)
{
	struct iommu_domain *iter_domain = NULL;
	unsigned long new_iova_alignment;
	unsigned long index;

	lockdep_assert_held_write(&iopt->rwsem);

	xa_for_each(&iopt->domains, index, iter_domain)
		if (iter_domain == domain)
			break;
	if (WARN_ON(iter_domain != domain) || index >= iopt->next_domain_id)
		return;

	/*
	 * Compress the xarray to keep it linear by swapping the entry to erase
	 * with the tail entry and shrinking the tail.
	 */
	iopt->next_domain_id--;
	iter_domain = xa_erase(&iopt->domains, iopt->next_domain_id);
	if (index != iopt->next_domain_id)
		xa_store(&iopt->domains, index, iter_domain, GFP_KERNEL);

	iopt_unfill_domain(iopt, domain);
	iopt_remove_reserved_iova(iopt, domain);

	/* Recalculate the iova alingment without the domain */
	new_iova_alignment = 1;
	xa_for_each (&iopt->domains, index, iter_domain)
		new_iova_alignment = max_t(unsigned long,
					   1UL << __ffs(domain->pgsize_bitmap),
					   new_iova_alignment);
	if (!WARN_ON(new_iova_alignment > iopt->iova_alignment))
		iopt->iova_alignment = new_iova_alignment;
}

/* Narrow the valid_iova_itree to include reserved ranges from a group. */
int iopt_table_enforce_group_iova(struct io_pagetable *iopt,
				  struct iommu_group *group)
{
	struct iommu_resv_region *resv;
	LIST_HEAD(group_resv_regions);
	int rc;

	down_write(&iopt->rwsem);
	rc = iommu_get_group_resv_regions(group, &group_resv_regions);
	if (rc)
		goto out_unlock;

	list_for_each_entry (resv, &group_resv_regions, list) {
		if (resv->type == IOMMU_RESV_DIRECT_RELAXABLE)
			continue;
		if (iopt_area_iter_first(iopt, resv->start,
					 resv->length - 1 + resv->start)) {
			rc = -EADDRINUSE;
			goto out_reserved;
		}
		rc = iopt_reserve_iova(iopt, resv->start,
				       resv->length - 1 + resv->start, group);
		if (rc)
			goto out_reserved;
	}
	rc = 0;
	goto out_free_resv;

out_reserved:
	iopt_remove_reserved_iova(iopt, group);
out_free_resv:
	while ((resv = list_first_entry_or_null(
			&group_resv_regions, struct iommu_resv_region, list))) {
		list_del(&resv->list);
		kfree(resv);
	}
out_unlock:
	up_write(&iopt->rwsem);
	return rc;
}
