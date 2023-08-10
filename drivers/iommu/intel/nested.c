// SPDX-License-Identifier: GPL-2.0
/*
 * nested.c - nested mode translation support
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Author: Lu Baolu <baolu.lu@linux.intel.com>
 *         Jacob Pan <jacob.jun.pan@linux.intel.com>
 */

#define pr_fmt(fmt)	"DMAR: " fmt

#include <linux/iommu.h>
#include <linux/pci.h>
#include <linux/pci-ats.h>

#include "iommu.h"
#include "pasid.h"

static int intel_nested_attach_dev(struct iommu_domain *domain,
				   struct device *dev)
{
	struct device_domain_info *info = dev_iommu_priv_get(dev);
	struct dmar_domain *dmar_domain = to_dmar_domain(domain);
	struct intel_iommu *iommu = info->iommu;
	unsigned long flags;
	int ret = 0;

	if (info->domain)
		device_block_translation(dev);

	if (iommu->agaw < dmar_domain->s2_domain->agaw) {
		dev_err_ratelimited(dev, "Adjusted guest address width not compatible\n");
		return -ENODEV;
	}

	/* Is s2_domain compatible with this IOMMU? */
	ret = prepare_domain_attach_device(&dmar_domain->s2_domain->domain, dev);
	if (ret) {
		dev_err_ratelimited(dev, "s2 domain is not compatible\n");
		return ret;
	}

	ret = domain_attach_iommu(dmar_domain, iommu);
	if (ret) {
		dev_err_ratelimited(dev, "Failed to attach domain to iommu\n");
		return ret;
	}

	ret = intel_pasid_setup_nested(iommu, dev,
				       PASID_RID2PASID, dmar_domain);
	if (ret) {
		domain_detach_iommu(dmar_domain, iommu);
		dev_err_ratelimited(dev, "Failed to setup pasid entry\n");
		return ret;
	}

	info->domain = dmar_domain;
	spin_lock_irqsave(&dmar_domain->lock, flags);
	list_add(&info->link, &dmar_domain->devices);
	spin_unlock_irqrestore(&dmar_domain->lock, flags);

	return 0;
}

static void intel_nested_domain_free(struct iommu_domain *domain)
{
	kfree(to_dmar_domain(domain));
}

static void intel_nested_invalidate(struct device *dev,
				    struct dmar_domain *domain,
				    u64 addr, unsigned long npages)
{
	struct device_domain_info *info = dev_iommu_priv_get(dev);
	struct intel_iommu *iommu = info->iommu;

	if (addr == 0 && npages == -1)
		intel_flush_iotlb_all(&domain->domain);
	else
		iommu_flush_iotlb_psi(iommu, domain,
				      addr >> VTD_PAGE_SHIFT,
				      npages, 1, 0);
}

static int intel_nested_cache_invalidate_user(struct iommu_domain *domain,
					      const struct iommu_user_data *user_data)
{
	const size_t min_len =
		offsetofend(struct iommu_hwpt_vtd_s1_invalidate, inv_data_uptr);
	struct dmar_domain *dmar_domain = to_dmar_domain(domain);
	struct iommu_hwpt_vtd_s1_invalidate inv_info;
	struct iommu_hwpt_vtd_s1_invalidate_desc req;
	struct device_domain_info *info;
	unsigned int entry_size;
	u32 entry_nr, index;
	unsigned long flags;
	u64 nr_uptr, uptr;
	int ret;

	ret = iommu_copy_user_data(&inv_info, user_data, sizeof(inv_info), min_len);
	if (ret)
		return ret;

	if (inv_info.flags)
		return -EINVAL;

	entry_size = inv_info.entry_size;
	nr_uptr = inv_info.entry_nr_uptr;
	uptr = inv_info.inv_data_uptr;

	if (get_user(entry_nr, (uint32_t __user *)u64_to_user_ptr(nr_uptr)))
		return -EFAULT;

	if (entry_size < dmar_domain->user_cache_inval_desc_min_size)
		return -EINVAL;

	for (index = 0; index < entry_nr; index++) {
		ret = copy_struct_from_user(&req, sizeof(req),
					    u64_to_user_ptr(uptr + index * entry_size),
					    entry_size);
		if (ret) {
			pr_err_ratelimited("Failed to fetch invalidation request\n");
			break;
		}

		if (req.__reserved || (req.flags & ~IOMMU_VTD_QI_FLAGS_LEAF) ||
		    !IS_ALIGNED(req.addr, VTD_PAGE_SIZE)) {
			ret = -EINVAL;
			break;
		}

		spin_lock_irqsave(&dmar_domain->lock, flags);
		list_for_each_entry(info, &dmar_domain->devices, link)
			intel_nested_invalidate(info->dev, dmar_domain,
						req.addr, req.npages);
		spin_unlock_irqrestore(&dmar_domain->lock, flags);
	}

	if (put_user(index, (uint32_t __user *)u64_to_user_ptr(nr_uptr)))
		return -EFAULT;

	return ret;
}

static const struct iommu_domain_ops intel_nested_domain_ops = {
	.attach_dev		= intel_nested_attach_dev,
	.free			= intel_nested_domain_free,
	.cache_invalidate_user	= intel_nested_cache_invalidate_user,
};

struct iommu_domain *intel_nested_domain_alloc(struct iommu_domain *s2_domain,
					       const struct iommu_user_data *user_data)
{
	const size_t min_len = offsetofend(struct iommu_hwpt_vtd_s1, __reserved);
	struct dmar_domain *s2_dmar_domain = to_dmar_domain(s2_domain);
	struct iommu_hwpt_vtd_s1 vtd;
	struct dmar_domain *domain;
	unsigned long flags;
	int ret;

	ret = iommu_copy_user_data(&vtd, user_data, sizeof(vtd), min_len);
	if (ret)
		return ERR_PTR(ret);

	domain = kzalloc(sizeof(*domain), GFP_KERNEL_ACCOUNT);
	if (!domain)
		return NULL;

	spin_lock_irqsave(&s2_dmar_domain->lock, flags);
	if (s2_dmar_domain->read_only_mapped) {
		spin_unlock_irqrestore(&s2_dmar_domain->lock, flags);
		pr_err_ratelimited("Nested configuration is disallowed when the stage-2 domain already has read-only mappings, due to HW errata (ERRATA_772415_SPR17)\n");
		kfree(domain);
		return NULL;
	}
	s2_dmar_domain->is_nested_parent = true;
	spin_unlock_irqrestore(&s2_dmar_domain->lock, flags);

	domain->use_first_level = true;
	domain->s2_domain = s2_dmar_domain;
	domain->s1_pgtbl = vtd.pgtbl_addr;
	domain->s1_cfg = vtd;
	/*
	 * The value should always be
	 * offsetofend(struct iommu_hwpt_vtd_s1_invalidate_desc, __reserved)
	 */
	*(size_t *)domain->user_cache_inval_desc_min_size =
		offsetofend(struct iommu_hwpt_vtd_s1_invalidate_desc, __reserved);
	domain->domain.ops = &intel_nested_domain_ops;
	domain->domain.type = IOMMU_DOMAIN_NESTED;
	INIT_LIST_HEAD(&domain->devices);
	spin_lock_init(&domain->lock);
	xa_init(&domain->iommu_array);

	return &domain->domain;
}
