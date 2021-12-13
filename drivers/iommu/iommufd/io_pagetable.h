// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES.
 *
 */
#ifndef __IO_PAGETABLE_H
#define __IO_PAGETABLE_H

#include <linux/interval_tree.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/xarray.h>

#include "iommufd_private.h"

struct iommu_domain;

void iopt_unfill_domain(struct io_pagetable *iopt, struct iommu_domain *domain);
int iopt_fill_domain(struct io_pagetable *iopt, struct iommu_domain *domain);

/*
 * Each io_pagetable is composed of intervals of areas which cover regions of
 * the iova that are backed by something. iova not covered by areas is not
 * populated in the page table. Each area is fully populated with pages.
 *
 * iovas are in byte units, but must be iopt->iova_alignemnt aligned.
 */
struct iopt_area {
	struct interval_tree_node node;
	struct interval_tree_node pages_node;
	struct io_pagetable *iopt;
	struct iopt_pages *pages;
	/* An arbitary domain that is storing the PFNs */
	struct iommu_domain *storage_domain;
	/* IOMMU_READ, IOMMU_WRITE, etc */
	int iommu_prot;
};

int iopt_area_fill_domains(struct iopt_area *area);
void iopt_area_unfill_domains(struct iopt_area *area);

static inline unsigned long iopt_area_index(struct iopt_area *area)
{
	return area->pages_node.start;
}

static inline unsigned long iopt_area_last_index(struct iopt_area *area)
{
	return area->pages_node.last;
}

static inline unsigned long iopt_area_iova(struct iopt_area *area)
{
	return area->node.start;
}

static inline unsigned long iopt_area_last_iova(struct iopt_area *area)
{
	return area->node.last;
}

static inline size_t iopt_area_length(struct iopt_area *area)
{
	return (area->node.last - area->node.start) + 1;
}

static inline struct iopt_area *iopt_area_iter_first(struct io_pagetable *iopt,
						     unsigned long start,
						     unsigned long last)
{
	struct interval_tree_node *node;

	node = interval_tree_iter_first(&iopt->area_itree, start, last);
	if (!node)
		return NULL;
	return container_of(node, struct iopt_area, node);
}

static inline struct iopt_area *iopt_area_iter_next(struct iopt_area *area,
						    unsigned long start,
						    unsigned long last)
{
	struct interval_tree_node *node;

	node = interval_tree_iter_next(&area->node, start, last);
	if (!node)
		return NULL;
	return container_of(node, struct iopt_area, node);
}

/*
 * This holds a pinned page list for an area of IO address space. The pages
 * always originate from a linear chunk of userspace VA. Multiple
 * io_pagetable's, through their iopt_area's, can share a single iopt_pages
 * which avoids multi-pinning and double accounting of page consumption.
 *
 * indexes in this structure are measured in PAGE_SIZE units, are 0 based from
 * the start of the uptr and extend to npages.
 */
struct iopt_pages {
	struct kref kref;
	struct mutex mutex;
	size_t npages;
	size_t npinned;
	struct mm_struct *source_mm;
	void __user *uptr;
	bool writable;

	struct xarray pinned_pfns;
	/* Of iopt_pages_user::node */
	struct rb_root_cached users_itree;
	/* Of iopt_area::pages_node */
	struct rb_root_cached domains_itree;
};

void iopt_pages_fill_from_xarray(struct iopt_pages *pages, unsigned long start,
				 unsigned long last, struct page **out_pages);
int iopt_pages_fill_xarray(struct iopt_pages *pages, unsigned long index,
			   unsigned long last, struct page **out_pages);
void iopt_pages_unfill_xarray(struct iopt_pages *pages, unsigned long index,
			      unsigned long last);

/*
 * Each interval represents an active iopt_access_pages(), it acts as an
 * interval lock that keeps the PFNs pinned and stored in the xarray.
 */
struct iopt_pages_user {
	struct interval_tree_node node;
	refcount_t refcount;
};

#endif
