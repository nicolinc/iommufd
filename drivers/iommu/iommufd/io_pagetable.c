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
#include <linux/rwsem.h>
#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/sched/mm.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/kref.h>
#include <linux/overflow.h>
#include <linux/interval_tree.h>
#include <linux/rwsem.h>
#include <linux/xarray.h>
#include <linux/sched.h>

#include "iommufd_private.h"

static void iommu_unmap_nofail(struct iommu_domain *domain, unsigned long iova,
			       size_t size)
{
	size_t ret;

	ret = iommu_unmap(domain, iova, size);
	/*
	 * It is a logic error in this code or a driver bug if the IOMMU unmaps
	 * something other than exactly as requested.
	 */
	WARN_ON(ret != size);
}

/*
 * An API to make a vector of PFNs, optimizing for contiguous pfns.
 */
struct iopt_accumulate {
	phys_addr_t *pfns;
	u16 *npfns;
	unsigned int array_size;
	unsigned int last;
	unsigned int total_pfns;
};

static int iopt_accumulate_init(struct iopt_accumulate *acum, size_t max_pages,
				void *backup, size_t backup_len)
{
	const size_t elmsz = sizeof(*acum->pfns) + sizeof(acum->npfns);

	acum->pfns = NULL;
	if (!backup || backup_len / elmsz < max_pages) {
		/*
		 * More memory makes the algorithms more efficient, but as this
		 * is performance don't try too hard to get it. A 64k page can
		 * hold about 26M of 4k pages and 13G of 2M pages
		 */
		acum->array_size = min_t(size_t, 65536 / elmsz, max_pages);
		acum->pfns = kmalloc(acum->array_size * elmsz,
				     GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
		if (!acum->pfns) {
			acum->array_size =
				min_t(size_t, PAGE_SIZE / elmsz, max_pages);
			acum->pfns =
				kmalloc(acum->array_size * elmsz, GFP_KERNEL);
		}
	}

	if (!acum->pfns) {
		if (!backup)
			return -ENOMEM;
		acum->array_size = backup_len / elmsz;
		acum->pfns = backup;
	}

	acum->npfns = (u16 *)(acum->pfns + acum->array_size);
	acum->last = 0;
	acum->total_pfns = 0;
	return 0;
}

static void iopt_accumulate_destroy(struct iopt_accumulate *acum, void *backup)
{
	if (acum->pfns != backup)
		kfree(acum->pfns);
}

static size_t iopt_accumulate_npfns(struct iopt_accumulate *acum)
{
	return acum->last + 1;
}

static bool iopt_accumulate_add_pfn(struct iopt_accumulate *acum,
				    phys_addr_t pfn)
{
	if (pfn == acum->pfns[acum->last] + acum->npfns[acum->last]) {
		acum->total_pfns++;
		if (acum->npfns[acum->last]++ == U16_MAX) {
			if (acum->last == acum->array_size - 1)
				return true;
			acum->last++;
			acum->pfns[acum->last] = pfn;
			acum->npfns[acum->last] = 0;
		}
	} else {
		if (acum->last == acum->array_size - 1)
			return true;
		acum->total_pfns++;
		acum->last++;
		acum->pfns[acum->last] = pfn;
		acum->npfns[acum->last] = 1;
	}
	return false;
}

/*
 * Read a list of pfns from a domain. This function is a bit peculiar to manage
 * the driver semantics around larger pages. It never reads a pfn past
 * last_iova, but it always accumulates full runs of consecutive pfns. Thus
 * npages can be exceeded if it ends in the middle of a large page. When the
 * unmapping logic uses this function it means we always unmap ending at a pfn
 * discontiguity, which mirrors the way the mapping was created in the first
 * place.
 */
static void iopt_accumulate_from_domain(struct iopt_accumulate *acum,
					struct iommu_domain *domain,
					unsigned long iova,
					unsigned long last_iova, size_t npages)
{
	phys_addr_t pfn;

	acum->total_pfns = 0;
	acum->last = 0;
	acum->pfns[0] = 0;
	acum->npfns[0] = 0;
	while (npages) {
		/*
		 * FIXME: This is pretty slow, it would be nice to get help from
		 * the driver here.
		 */
		pfn = iommu_iova_to_phys(domain, iova);
		if (iopt_accumulate_add_pfn(acum, pfn))
			return;
		if (last_iova - iova < PAGE_SIZE)
			return;
		iova += PAGE_SIZE;
		npages--;
	}
}

static void iopt_accumulate_from_xarray(struct iopt_accumulate *acum,
					struct xarray *xa, unsigned long index,
					unsigned long last, size_t npages)
{
	phys_addr_t pfn;

	acum->total_pfns = 0;
	acum->last = 0;
	acum->pfns[0] = 0;
	acum->npfns[0] = 0;
	while (npages && index <= last) {
		XA_STATE(xas, xa, index);
		void *entry;

		xas_lock(&xas);
		xas_for_each (&xas, entry, last) {
			pfn = xa_to_value(entry);
			if (iopt_accumulate_add_pfn(acum, pfn)) {
				xas_unlock(&xas);
				return;
			}
			index++;
			npages--;
			if (!npages)
				break;
		}
		xas_unlock(&xas);
	}
}

static int iopt_accumulate_to_domain(struct iopt_accumulate *acum,
				     struct iommu_domain *domain,
				     unsigned long iova, int iommu_prot)
{
	unsigned long start_iova = iova;
	unsigned int cur = 0;
	int rc;

	while (cur <= acum->last) {
		rc = iommu_map(domain, iova, acum->pfns[cur],
			       acum->npfns[cur] * PAGE_SIZE, iommu_prot);
		if (rc) {
			if (start_iova != iova)
				iommu_unmap_nofail(domain, start_iova,
						   iova - start_iova);
			return rc;
		}
		iova += acum->npfns[cur] * PAGE_SIZE;
		cur++;
	}
	return 0;
}

static void iopt_accumulate_unpin(struct iopt_accumulate *acum,
				  struct mm_struct *mm, bool writable,
				  unsigned int offset, size_t npages)
{
	unsigned int cur = 0;

	while (offset) {
		if (acum->npfns[cur] < offset)
			break;
		offset -= acum->npfns[cur];
		cur++;
	}

	while (npages) {
		size_t to_unpin =
			min_t(size_t, npages, acum->npfns[cur] - offset);

		unpin_user_page_range_dirty_lock(
			pfn_to_page(acum->pfns[cur] + offset), to_unpin,
			writable);
		cur++;
		offset = 0;
		npages -= to_unpin;
	}
}

/*
 * Each io_pagetable is composed of intervals of areas which cover regions of
 * the iova that are backed by something. iova not covered by areas is not
 * populated in the page table. Each area is fully populated with pages.
 *
 * iovas are in byte units, but must be IO page aligned.
 */
struct iopt_area {
	struct interval_tree_node node;
	struct io_pagetable *iopt;
	struct iopt_pages *pages;
	struct list_head pages_item;
	atomic_t num_users;
	/* IOMMU_READ, IOMMU_WRITE, etc */
	int iommu_prot;
};

/*
 * This holds a pinned page list for an area of IO address space. The pages
 * always originate from a linear chunk of userspace VA. Multiple io_pagetable's
 * through their iopt_area's can share a single iopt_pages which avoids
 * multi-pinning and double accounting of page consumption.
 *
 * If any io_pagetable has a domain then the domain must have a fully populated
 * list of PFNs in this pages. In this case the domain becomes the backing store
 * for the pfn list.
 *
 * For non-domain io_pagetables the list of pages is stored in the pinned_pfns
 * xarray and a record of users is kept in the users_itree. The union of all
 * intervals in the users_itree represents the populated PFNs, while the holes
 * in users_itree that are not covered by any interverals represents user va
 * that is not currently pinned.
 *
 * As io_pagetables can be attached/removed at any time the iopt_pages can shift
 * between domain backed and pinned_pfns back during its lifecycle.
 *
 * index's in this structures are measured in PAGE_SIZE units, are 0 based from
 * the start of the uptr and extend to npages.
 */
struct iopt_pages {
	struct kref kref;
	// FIXME doesn't seem to be any readers, use a mutex
	struct rw_semaphore rwsem;
	size_t npages;
	struct mm_struct *source_mm;
	void __user *uptr;
	bool writable;

	struct list_head domain_areas;
	struct list_head sw_areas;
	struct xarray pinned_pfns;
	struct rb_root_cached users_itree;
};

/*
 * Each interval represents an active iopt_access_pages(), it acts as an
 * interval lock that keeps the pfns pined and in the xarray.
 */
struct iopt_pages_user {
	struct interval_tree_node node;
	refcount_t refcount;
};

static struct iopt_area *iopt_area_iter_first(struct io_pagetable *iopt,
					      unsigned long start,
					      unsigned long last)
{
	struct interval_tree_node *node;

	node = interval_tree_iter_first(&iopt->area_itree, start, last);
	if (!node)
		return NULL;
	return container_of(node, struct iopt_area, node);
}

static struct iopt_area *iopt_area_iter_next(struct iopt_area *area,
					     unsigned long start,
					     unsigned long last)
{
	struct interval_tree_node *node;

	node = interval_tree_iter_next(&area->node, start, last);
	if (!node)
		return NULL;
	return container_of(node, struct iopt_area, node);
}

static unsigned long iopt_area_iova(struct iopt_area *area)
{
	return area->node.start;
}

static unsigned long iopt_area_last_iova(struct iopt_area *area)
{
	return area->node.last;
}

static size_t iopt_area_length(struct iopt_area *area)
{
	return (area->node.last - area->node.start) + 1;
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

static unsigned long iopt_index_to_iova(struct iopt_area *area,
					unsigned long index)
{
	return iopt_area_iova(area) + index * PAGE_SIZE;
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
	INIT_LIST_HEAD(&pages->domain_areas);
	INIT_LIST_HEAD(&pages->sw_areas);
	xa_init(&pages->pinned_pfns);
	init_rwsem(&pages->rwsem);
	pages->source_mm = current->mm;
	mmgrab(pages->source_mm);
	pages->uptr = (void __user *)ALIGN_DOWN((uintptr_t)uptr, PAGE_SIZE);
	pages->npages = DIV_ROUND_UP(length + (uptr - pages->uptr), PAGE_SIZE);
	pages->users_itree = RB_ROOT_CACHED;
	pages->writable = writable;

	return pages;
}

static void iopt_release_pages(struct kref *kref)
{
	struct iopt_pages *pages = container_of(kref, struct iopt_pages, kref);

	WARN_ON(!list_empty(&pages->domain_areas));
	WARN_ON(!list_empty(&pages->sw_areas));
	mmdrop(pages->source_mm);
	kfree(pages);
}

static void iopt_put_pages(struct iopt_pages *pages)
{
	kref_put(&pages->kref, iopt_release_pages);
}

static struct iommu_domain *iopt_get_any_domain(struct io_pagetable *iopt)
{
	struct iommu_domain *domain = xa_load(&iopt->domains, 0);

	lockdep_assert_held(&iopt->rwsem);

	WARN_ON(!domain);
	return domain;
}

static void iopt_area_unpin_domain(struct iopt_area *area,
				   struct iommu_domain *domain)
{
	struct iopt_accumulate acum;
	struct iopt_pages *pages = area->pages;
	struct interval_tree_span_iter span;
	unsigned long unmap_start = 0;
	unsigned long unmap_end = 0;
	unsigned long acum_start = 0;
	unsigned long unpin_end = 0;
	u64 backup[32];

	iopt_accumulate_init(&acum, pages->npages, backup, sizeof(backup));

	/*
	 * Walk through the list of pfns stored in a domain and unpin only those
	 * pfns that are not covered by an iopt_pages_user. This requires
	 * reading batches of pages from the domain, and then intersecting the
	 * span of each batch with holes in the users_itree. This batches the
	 * unmaps to cover both the spans of pfns that could be read and the
	 * still-pinned spanes from the iopt_pages_users's.
	 */
	for (interval_tree_span_iter_first(&span, &pages->users_itree, 0,
					   pages->npages - 1);
	     interval_tree_span_iter_done(&span);) {
		size_t to_unpin;

		if (!span.is_hole) {
			unpin_end = span.last_used + 1;
			interval_tree_span_iter_next(&span);
			continue;
		}

		if (unpin_end >= unmap_end) {
			acum_start = unpin_end;
			iopt_accumulate_from_domain(
				&acum, domain,
				iopt_index_to_iova(area, unpin_end),
				iopt_area_last_iova(area),
				span.last_hole - unpin_end + 1);
			unmap_end = unpin_end + iopt_accumulate_npfns(&acum);
			iommu_unmap_nofail(
				domain, iopt_index_to_iova(area, unmap_start),
				(unmap_end - unmap_start) * PAGE_SIZE);
			unmap_start = unmap_end;
		}

		to_unpin = min_t(size_t,
				 iopt_accumulate_npfns(&acum) -
					 (unpin_end - acum_start),
				 span.last_hole - unpin_end + 1);
		iopt_accumulate_unpin(&acum, pages->source_mm, pages->writable,
				      unpin_end - acum_start, to_unpin);
		unpin_end += to_unpin;
		if (unpin_end > span.last_hole)
			interval_tree_span_iter_next(&span);
	}
	if (unmap_start != pages->npages)
		iommu_unmap_nofail(domain,
				   iopt_index_to_iova(area, unmap_start),
				   (pages->npages - unmap_start) * PAGE_SIZE);
	iopt_accumulate_destroy(&acum, backup);
}

static int iopt_area_pin_domain(struct iopt_area *area,
				struct iommu_domain *domain,
				struct iopt_pages *pages)
{
	/* FIXME: pin and load the pfns under pages into area->owner->domain */
	return WARN_ON(-EOPNOTSUPP);
}

/*
 * Undoes iopt_set_area_pages(). This unmaps the pages from the area's IOVA and
 * disconnects the page list from the area.
 */
static void iopt_remove_area_pages(struct iopt_area *area)
{
	struct iopt_pages *pages = area->pages;
	struct iommu_domain *domain;
	unsigned long index = 0;

	down_write(&pages->rwsem);
	if (xa_empty(&area->iopt->domains)) {
		WARN_ON(atomic_read(&area->num_users));
		list_del_init(&area->pages_item);
		goto out_unlock;
	}

	if (list_first_entry_or_null(&pages->domain_areas, struct iopt_area,
				     pages_item)) {
		/*
		 * Another domain is still holding all the pfns, so just fast
		 * clear it and be done.
		 */
		xa_for_each (&area->iopt->domains, index, domain)
			iommu_unmap_nofail(domain, iopt_area_iova(area),
					   iopt_area_length(area));
		goto out_unlock;
	}

	xa_for_each (&area->iopt->domains, index, domain) {
		/*
		 * Domains prior to the last are simply bulk unmapped as the
		 * last one continues to hold the pfns. The last domain releases
		 * the pin. Note that all domains must be unmapped before unpin.
		 */
		if (index == area->iopt->last_domain_id)
			iopt_area_unpin_domain(area, domain);
		else
			iommu_unmap_nofail(domain, iopt_area_iova(area),
					   iopt_area_length(area));
	}

out_unlock:
	up_write(&pages->rwsem);
}

/*
 * Copy the PFNs from the src domain to the dst domain. The src domain already
 * holds a pin and has extracted them from uptr.
 */
static int iopt_area_copy_domain(struct iopt_area *dst,
				 struct iommu_domain *dst_domain,
				 struct iopt_area *src,
				 struct iommu_domain *src_domain)
{
	struct iopt_accumulate acum;
	unsigned long index = 0;
	size_t npages = dst->pages->npages;
	int rc;

	if (WARN_ON(iopt_area_length(dst) != iopt_area_length(src)))
		return -EINVAL;

	rc = iopt_accumulate_init(&acum, npages, NULL, 0);
	if (rc)
		return rc;
	for (index = 0; index != npages;) {
		iopt_accumulate_from_domain(&acum, src_domain,
					    iopt_index_to_iova(src, index),
					    iopt_area_last_iova(src), SIZE_MAX);
		rc = iopt_accumulate_to_domain(&acum, dst_domain,
					       iopt_index_to_iova(dst, index),
					       dst->iommu_prot);
		if (rc) {
			iommu_unmap_nofail(dst_domain, iopt_area_iova(dst),
					   index * PAGE_SIZE);
			iopt_accumulate_destroy(&acum, NULL);
			return rc;
		}
		index += iopt_accumulate_npfns(&acum);
	}
	iopt_accumulate_destroy(&acum, NULL);
	return 0;
}

/*
 * Assign the page list to an area. After this returns the area's iova will have
 * the pages mapped from userspace.
 */
static int iopt_set_area_pages(struct iopt_area *area, struct iopt_pages *pages)
{
	struct iopt_area *existing_domain_area;
	struct iommu_domain *first_domain = NULL;
	unsigned long unmap_index = 0;
	struct iommu_domain *domain;
	unsigned long index = 0;
	int rc;

	if ((area->iommu_prot & IOMMU_WRITE) && !pages->writable)
		return -EPERM;

	down_write(&pages->rwsem);

	if (xa_empty(&area->iopt->domains)) {
		/* SW areas do not pin pages when the area is created */
		list_add(&area->pages_item, &pages->sw_areas);
		rc = 0;
		goto out_unlock;
	}

	existing_domain_area = list_first_entry_or_null(
		&pages->domain_areas, struct iopt_area, pages_item);
	if (existing_domain_area)
		first_domain = iopt_get_any_domain(existing_domain_area->iopt);

	/*
	 * FIXME: This would have better performance to batch each pin/copy and
	 * then write the batch to each clone.
	 */
	xa_for_each (&area->iopt->domains, index, domain) {
		if (!first_domain) {
			rc = iopt_area_pin_domain(area, domain, pages);
			if (rc)
				goto out_unmap;
			first_domain = domain;
		} else {
			rc = iopt_area_copy_domain(area, domain, area,
						   first_domain);
			if (rc)
				goto out_unmap;
		}
	}
	area->pages = pages;
	list_add(&area->pages_item, &pages->domain_areas);
	rc = 0;
	goto out_unlock;

out_unmap:
	xa_for_each (&area->iopt->domains, unmap_index, domain) {
		if (index == 0 && !existing_domain_area)
			iopt_area_unpin_domain(area, domain);
		else
			iommu_unmap_nofail(domain, iopt_area_iova(area),
					   iopt_area_length(area));
	}
out_unlock:
	up_write(&pages->rwsem);
	return rc;
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

	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (!area)
		return ERR_PTR(-ENOMEM);
	area->node.start = iova;
	area->node.last = iova_end;
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
				    unsigned long iova_alignment)
{
	if (!span->is_hole || span->last_hole - span->start_hole < length - 1)
		return false;

	span->start_hole = ALIGN(span->start_hole, iova_alignment);
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
	struct interval_tree_span_iter area_span;
	unsigned long iova_alignment;

	lockdep_assert_held(&iopt->rwsem);

	if (length == 0 || length >= ULONG_MAX/2)
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
		if (!__alloc_iova_check_hole(&area_span, length,
					     iova_alignment))
			continue;

		for (interval_tree_span_iter_first(
			     &reserved_span, &iopt->reserved_iova_itree,
			     area_span.start_hole, area_span.last_hole);
		     !interval_tree_span_iter_done(&reserved_span);
		     interval_tree_span_iter_next(&reserved_span)) {
			if (!__alloc_iova_check_hole(&reserved_span, length,
						     iova_alignment))
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

	if (WARN_ON(iopt_area_iova(area) != iova ||
		    iopt_area_last_iova(area) != iova + length - 1)) {
		rc = -EINVAL;
		goto out_free_area;
	}

	rc = iopt_set_area_pages(area, pages);
	if (rc)
		goto out_free_area;

	interval_tree_insert(&area->node, &iopt->area_itree);
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

	rc = iopt_set_area_pages(area, pages);
	if (rc)
		goto out_free_area;

	interval_tree_insert(&area->node, &dst->area_itree);

	return 0;

out_free_area:
	iopt_free_area(area);
	return rc;
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

	/* Drivers have to unpin on notification. */
	if (WARN_ON(atomic_read(&area->num_users))) {
		rc = -EBUSY;
		goto out_unlock;
	}

	iopt_remove_area_pages(area);
	interval_tree_remove(&area->node, &iopt->area_itree);
	iopt_free_area(area);
	rc = 0;

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
		/* Drivers have to unpin on notification. */
		if (WARN_ON(atomic_read(&area->num_users))) {
			rc = -EBUSY;
			goto out_unlock;
		}

		iopt_remove_area_pages(area);
		interval_tree_remove(&area->node, &iopt->area_itree);
		iopt_free_area(area);
	}
	rc = 0;

out_unlock:
	up_write(&iopt->rwsem);
	return rc;
}

/*
 * Erase entries in the pinned_pfns xarray that are not covered by any users.
 * This does not unpin the pages, the caller is responsible to deal with the pin
 * reference. The main purpose of this action is to save memory in the xarray.
 */
static void iopt_pages_clean_xarray(struct iopt_pages *pages,
				    unsigned long index, unsigned long last)
{
	struct interval_tree_span_iter span;

	for (interval_tree_span_iter_first(&span, &pages->users_itree, index,
					   last);
	     interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span)) {
		XA_STATE(xas, &pages->pinned_pfns, span.start_hole);
		void *entry;

		if (!span.is_hole)
			continue;
		xas_lock(&xas);
		xas_for_each (&xas, entry, span.last_hole)
			xas_store(&xas, NULL);
		xas_unlock(&xas);
	}
}

/*
 * Like iopt_pages_clean_xarray() except this also unpins the pages which are
 * removed from the xarray.
 */
static void iopt_pages_unpin_xarray(struct iopt_pages *pages,
				    unsigned long index, unsigned long last)
{
	struct interval_tree_span_iter span;
	struct iopt_accumulate acum;
	u64 backup[32];

	iopt_accumulate_init(&acum, pages->npages, backup, sizeof(backup));
	for (interval_tree_span_iter_first(&span, &pages->users_itree, index,
					   last);
	     interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span)) {
		unsigned long unpin_end;

		if (!span.is_hole)
			continue;

		unpin_end = span.start_hole;
		while (unpin_end <= span.last_hole) {
			size_t to_unpin;

			iopt_accumulate_from_xarray(
				&acum, &pages->pinned_pfns, unpin_end,
				span.last_hole, span.last_hole - unpin_end + 1);

			to_unpin = min_t(size_t, iopt_accumulate_npfns(&acum),
					 span.last_hole - unpin_end + 1);
			iopt_accumulate_unpin(&acum, pages->source_mm,
					      pages->writable, 0, to_unpin);
			unpin_end += to_unpin;
		}
	}
	iopt_accumulate_destroy(&acum, backup);
}

static int iopt_pages_fill_pinned_pfns(struct iopt_pages *pages,
				       unsigned long index, size_t npages,
				       struct page **out_pages, bool write)
{
	struct iopt_area *domain_area = list_first_entry_or_null(
		&pages->domain_areas, struct iopt_area, pages_item);
	unsigned long orig_last = index + npages - 1;
	unsigned long orig_index = index;
	void *old;

	if (domain_area) {
		struct iommu_domain *domain =
			iopt_get_any_domain(domain_area->iopt);
		unsigned long iova = iopt_index_to_iova(domain_area, index);

		/*
		 * A domain has already pinned the pages, just read them out. We
		 * have to populate the xarray here as we rely on the xarray to
		 * hold the pfns if all the domains are destroyed and we cannot
		 * allocate memory during domain disconnect as that can fail.
		 * FIXME: this could be further optimized by using the xarray
		 * multi interface, but that is quite tricky.
		 */
		for (; npages;
		     index++, iova += PAGE_SIZE, npages--, out_pages++) {
			phys_addr_t pfn;

			/* FIXME: we could do a hole iteration here and avoid
			 * this work for pfns already in the xarray
			 * FIXME: we could batch and use the xas interface */
			pfn = iommu_iova_to_phys(domain, iova);
			*out_pages = pfn_to_page(pfn);
			old = xa_store(&pages->pinned_pfns, index,
				       xa_mk_value(pfn), GFP_KERNEL);
			if (xa_is_err(old)) {
				iopt_pages_clean_xarray(pages, orig_index,
							orig_last);
				return xa_err(old);
			}
		}
		return 0;
	}

	/* FIXME: have to pin the pages and load them into the xarray */

	return 0;
}

static struct iopt_pages_user *
iopt_pages_get_exact_user(struct iopt_pages *pages, unsigned long index,
			  unsigned long last)
{
	struct interval_tree_node *node;

	/* There can be overlapping ranges in this interval tree */
	for (node = interval_tree_iter_first(&pages->users_itree, index, last);
	     node; node = interval_tree_iter_next(node, index, last))
		if (node->start == index && node->last == last)
			return container_of(node, struct iopt_pages_user, node);
	return NULL;
}

static int iopt_pages_add_user(struct iopt_pages *pages, unsigned long index,
			       size_t npages, struct page **out_pages,
			       bool write)
{
	unsigned long last = index + npages - 1;
	struct iopt_pages_user *user;
	int rc;

	if (pages->writable != write)
		return -EPERM;

	down_write(&pages->rwsem);
	user = iopt_pages_get_exact_user(pages, index, last);
	if (user) {
		refcount_inc(&user->refcount);
		rc = 0;
		goto out_unlock;
	}

	user = kzalloc(sizeof(*user), GFP_KERNEL);
	if (!user) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	rc = iopt_pages_fill_pinned_pfns(pages, index, npages, out_pages,
					 write);
	if (rc)
		goto out_free;

	user->node.start = index;
	user->node.last = last;
	refcount_set(&user->refcount, 1);
	interval_tree_insert(&user->node, &pages->users_itree);
	rc = 0;

out_free:
	kfree(user);
out_unlock:
	up_write(&pages->rwsem);
	return rc;
}

static void iopt_pages_remove_user(struct iopt_pages *pages,
				   unsigned long index, size_t npages)
{
	unsigned long last = index + npages - 1;
	struct iopt_pages_user *user;

	down_write(&pages->rwsem);
	user = iopt_pages_get_exact_user(pages, index, last);
	if (WARN_ON(!user))
		goto out_unlock;

	if (!refcount_dec_and_test(&user->refcount))
		goto out_unlock;

	/* A domain is holding the pins, just free the xarray entries */
	if (list_first_entry_or_null(&pages->domain_areas, struct iopt_area,
				     pages_item)) {
		iopt_pages_clean_xarray(pages, index, last);
		goto out_unlock;
	}
	iopt_pages_unpin_xarray(pages, index, last);

out_unlock:
	up_write(&pages->rwsem);
}

/**
* iopt_access_pages - Return a list of pages under the iova
*
* Reads @npages starting at iova and returns the struct page * pointers. These
* can be kmap'd by the caller for CPU access.
*
* The caller must perform iopt_unaccess_pages() when done to balance this.
*
* CHECKME: callers that need a DMA mapping via a sgl should create another
* interface to build the SGL efficiently)
*/
int iopt_access_pages(struct io_pagetable *iopt, unsigned long iova,
		      size_t npages, struct page **out_pages, bool write)
{
	unsigned long cur_iova;
	unsigned long iova_end;
	struct iopt_area *area;
	size_t length;
	int rc;

	down_read(&iopt->rwsem);
	if (!npages || iova % PAGE_SIZE)
		return -EINVAL;
	if (check_mul_overflow(npages, PAGE_SIZE, &length) ||
	    check_add_overflow(iova, length - 1, &iova_end))
		return -EOVERFLOW;

	cur_iova = iova;
	for (area = iopt_area_iter_first(iopt, iova, iova_end); area;
	     area = iopt_area_iter_next(area, iova, iova_end)) {
		unsigned long intr_start = max(iova, iopt_area_iova(area));
		unsigned long intr_end =
			min(iova_end, iopt_area_last_iova(area));
		size_t npages = (intr_end - intr_start + 1) / PAGE_SIZE;

		/* Need contiguous areas un the access */
		if (cur_iova != intr_start) {
			rc = -EINVAL;
			goto out_remove;
		}

		npages = (intr_end - intr_start + 1) / PAGE_SIZE;
		rc = iopt_pages_add_user(
			area->pages,
			(intr_start - iopt_area_iova(area)) / PAGE_SIZE, npages,
			out_pages + (intr_end - iopt_area_iova(area) + 1) /
					    PAGE_SIZE,
			write);
		if (rc)
			goto out_remove;
		cur_iova += npages * PAGE_SIZE;
		atomic_inc(&area->num_users);
	}

	up_read(&iopt->rwsem);
	return 0;

out_remove:
	iopt_unaccess_pages(iopt, iova, (cur_iova - iova) / PAGE_SIZE);
	return rc;
}

/**
 * iopt_unaccess_pages - Undo iopt_access_pages
 *
 * Return the struct page's. The caller must stop accessing them before calling
 * this.
 */
void iopt_unaccess_pages(struct io_pagetable *iopt, unsigned long iova,
			 size_t npages)
{
	unsigned long cur_iova;
	unsigned long iova_end;
	struct iopt_area *area;
	size_t length;

	down_read(&iopt->rwsem);
	if (!npages || iova % PAGE_SIZE)
		return;
	if (check_mul_overflow(npages, PAGE_SIZE, &length) ||
	    check_add_overflow(iova, length - 1, &iova_end))
		return;

	cur_iova = iova;
	for (area = iopt_area_iter_first(iopt, iova, iova_end); area;
	     area = iopt_area_iter_next(area, iova, iova_end)) {
		unsigned long intr_start = max(iova, iopt_area_iova(area));
		unsigned long intr_end =
			min(iova_end, iopt_area_last_iova(area));
		size_t npages = (intr_end - intr_start + 1) / PAGE_SIZE;
		int num_users;

		/* Need contiguous areas un the access */
		if (WARN_ON(cur_iova != intr_start))
			return;

		iopt_pages_remove_user(area->pages,
				       (intr_start - iopt_area_iova(area)) /
					       PAGE_SIZE,
				       npages);
		cur_iova += npages * PAGE_SIZE;

		num_users = atomic_dec_return(&area->num_users);
		WARN_ON(num_users < 0);
	}
	up_read(&iopt->rwsem);
}

struct iopt_reserved_iova {
	struct interval_tree_node node;
	void *owner;
};

static int iopt_reserve_iova(struct io_pagetable *iopt, unsigned long start,
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

static void iopt_remove_reserved_iova(struct io_pagetable *iopt, void *owner)
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
	int rc;

	init_rwsem(&iopt->rwsem);
	iopt->area_itree = RB_ROOT_CACHED;
	iopt->reserved_iova_itree = RB_ROOT_CACHED;

	/* SW tables have no alignment restriction */
	iopt->iova_alignment = 1;

	/*
	 * iopt's start as SW tables that can use the entire size_t IOVA space
	 * due to the use of size_t in the APIs. FIXME: The last page is chopped
	 * off out of caution that edge cases around overflow are not fully
	 * tested.
	 */
	rc = iopt_reserve_iova(iopt, SIZE_MAX - PAGE_SIZE + 1, SIZE_MAX, NULL);
	if (rc) {
		iopt_destroy_table(iopt);
		return rc;
	}
	return 0;
}

void iopt_destroy_table(struct io_pagetable *iopt)
{
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

static void iopt_unpopulate_domain(struct io_pagetable *iopt,
				   struct iommu_domain *domain,
				   unsigned long last)
{
	bool domain_to_sw = iopt->last_domain_id == 0;
	struct iopt_area *area;

	for (area = iopt_area_iter_first(iopt, 0, last); area;
	     area = iopt_area_iter_next(area, 0, last)) {
		if (domain_to_sw) {
			iopt_area_unpin_domain(area, domain);
			list_del(&area->pages_item);
			list_add(&area->pages_item, &area->pages->sw_areas);
		} else {
			iommu_unmap_nofail(domain, iopt_area_iova(area),
					   iopt_area_length(area));
		}
	}
}

static int iopt_populate_new_domain(struct io_pagetable *iopt,
				    struct iommu_domain *domain)
{
	struct iommu_domain *existing_domain = xa_load(&iopt->domains, 0);
	struct iopt_area *area;
	int rc;

	for (area = iopt_area_iter_first(iopt, 0, ULONG_MAX); area;
	     area = iopt_area_iter_next(area, 0, ULONG_MAX)) {
		if (!existing_domain) {
			rc = iopt_area_pin_domain(area, domain, area->pages);
			if (rc)
				goto out_unmap;
			list_del(&area->pages_item);
			list_add(&area->pages_item, &area->pages->domain_areas);
		} else {
			rc = iopt_area_copy_domain(area, domain, area,
						   existing_domain);
			if (rc)
				goto out_unmap;
		}
	}
	return 0;

out_unmap:
	if (iopt_area_iova(area) != 0)
		iopt_unpopulate_domain(iopt, domain, iopt_area_iova(area) - 1);
	return rc;
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
		if (!rc)
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
	if (geometry->aperture_end != ULONG_MAX) {
		if (iopt_area_iter_first(iopt, geometry->aperture_end + 1,
					 ULONG_MAX))
			return -EADDRINUSE;
		rc = iopt_reserve_iova(iopt, geometry->aperture_end + 1,
				       ULONG_MAX, domain);
		if (rc)
			goto out_reserved;
	}

	rc = iopt_populate_new_domain(iopt, domain);
	if (rc)
		goto out_reserved;

	iopt->iova_alignment = new_iova_alignment;
	rc = xa_err(xa_store(&iopt->domains, iopt->last_domain_id, domain,
			     GFP_KERNEL));
	if (rc)
		goto out_unpopulate;
	iopt->last_domain_id++;

	return 0;
out_unpopulate:
	iopt_unpopulate_domain(iopt, domain, ULONG_MAX);
out_reserved:
	iopt_remove_reserved_iova(iopt, domain);
	return rc;
}

void iopt_table_remove_domain(struct io_pagetable *iopt,
			      struct iommu_domain *domain)
{
	struct iommu_domain *iter_domain = NULL;
	unsigned long index = 0;

	lockdep_assert_held_write(&iopt->rwsem);

	xa_for_each(&iopt->domains, index, iter_domain)
		if (iter_domain == domain)
			break;
	if (WARN_ON(iter_domain != domain) || index >= iopt->last_domain_id)
		return;

	/*
	 * Compress the xarray to keep it linear by swapping the entry to erase
	 * with the tail entry then shrinking the tail.
	 */
	if (index + 1 == iopt->last_domain_id) {
		xa_erase(&iopt->domains, index);
	} else {
		iter_domain = xa_erase(&iopt->domains, iopt->last_domain_id);
		xa_store(&iopt->domains, index, iter_domain, GFP_KERNEL);
	}
	iopt->last_domain_id--;

	iopt_unpopulate_domain(iopt, domain, ULONG_MAX);
	iopt_remove_reserved_iova(iopt, domain);
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
