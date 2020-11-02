// SPDX-License-Identifier: GPL-2.0
/*
 * arm-smmu-v3-nested.c - nested translation support
 *
 * Copyright (C) 2018-2022, Red Hat
 * Copyright (c) 2022-2023, NVIDIA CORPORATION & AFFILIATES
 *
 * Author: Eric Auger <eric.auger@redhat.com>
 *         Nicolin Chen <baolu.lu@linux.intel.com>
 */

#include "arm-smmu-v3.h"

static void arm_smmu_iotlb_sync_user(struct iommu_domain *domain,
				     void *user_data)
{
	struct iommu_hwpt_invalidate_arm_smmuv3 *inv_info = user_data;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_cmdq_ent cmd;
	unsigned long iova = 0;
	size_t granule_size;
	size_t size = 0;
	int ssid = 0;

	if (domain->type != IOMMU_DOMAIN_NESTED || !smmu_domain->s2)
		return;

	if (!smmu || !inv_info)
		return;

	cmd.opcode = inv_info->opcode;
	granule_size = inv_info->granule_size;

	switch (inv_info->opcode) {
	case CMDQ_OP_CFGI_CD:
	case CMDQ_OP_CFGI_CD_ALL:
		return arm_smmu_sync_cd(smmu_domain, inv_info->ssid, true);
	case CMDQ_OP_TLBI_NH_VA:
		if (!granule_size || !(granule_size & smmu->pgsize_bitmap) ||
		    granule_size & ~(1ULL << __ffs(granule_size)))
			return;

		iova = inv_info->range.start;
		size = inv_info->range.last - inv_info->range.start + 1;
		if (!size)
			return;

		cmd.tlbi.asid = inv_info->asid;
		cmd.tlbi.vmid = smmu_domain->s2->s2_cfg.vmid;
		cmd.tlbi.leaf = inv_info->flags & IOMMU_SMMUV3_CMDQ_TLBI_VA_LEAF;
		__arm_smmu_tlb_inv_range(&cmd, iova, size, granule_size, smmu_domain);
		break;
	case CMDQ_OP_TLBI_NH_ASID:
		cmd.tlbi.asid = inv_info->asid;
		fallthrough;
	case CMDQ_OP_TLBI_NSNH_ALL:
		cmd.tlbi.vmid = smmu_domain->s2->s2_cfg.vmid;
		arm_smmu_cmdq_issue_cmd_with_sync(smmu, &cmd);
		break;
	case CMDQ_OP_ATC_INV:
		ssid = inv_info->ssid;
		iova = inv_info->range.start;
		size = inv_info->range.last - inv_info->range.start + 1;
		break;
	default:
		return;
	}

	arm_smmu_atc_inv_domain(smmu_domain, ssid, iova, size);
}

static const struct iommu_domain_ops arm_smmu_nested_domain_ops = {
	.attach_dev		= arm_smmu_attach_dev,
	.free			= arm_smmu_domain_free,
	.iotlb_sync_user	= arm_smmu_iotlb_sync_user,
};

struct iommu_domain *
arm_smmu_nested_domain_alloc(struct iommu_domain *s2_domain,
			     const void *user_data)
{
	const struct iommu_hwpt_arm_smmuv3 *alloc = user_data;
	struct arm_smmu_domain *s2, *smmu_domain;
	struct iommu_domain *domain;

	/* Only allows a nested stage-1 domain */
	if (!alloc || alloc->flags & IOMMU_SMMUV3_FLAG_S2)
		return NULL;

	s2 = to_smmu_domain(s2_domain);

	mutex_lock(&s2->init_mutex);
	if (s2->stage != ARM_SMMU_DOMAIN_S2) {
		mutex_unlock(&s2->init_mutex);
		return NULL;
	}
	mutex_unlock(&s2->init_mutex);

	if (alloc->config != IOMMU_SMMUV3_CONFIG_ABORT &&
	    alloc->config != IOMMU_SMMUV3_CONFIG_BYPASS &&
	    alloc->config != IOMMU_SMMUV3_CONFIG_TRANSLATE)
		return NULL;

	domain = arm_smmu_domain_alloc(IOMMU_DOMAIN_NESTED);
	if (!domain)
		return NULL;
	domain->type = IOMMU_DOMAIN_NESTED;
	domain->ops = &arm_smmu_nested_domain_ops;

	smmu_domain = to_smmu_domain(domain);
	mutex_lock(&smmu_domain->init_mutex);

	smmu_domain->s2 = s2;
	smmu_domain->stage = ARM_SMMU_DOMAIN_S1;

	switch (alloc->config) {
	case IOMMU_SMMUV3_CONFIG_ABORT:
		smmu_domain->bypass = false;
		smmu_domain->abort = true;
		break;
	case IOMMU_SMMUV3_CONFIG_BYPASS:
		smmu_domain->bypass = true;
		smmu_domain->abort = false;
		break;
	case IOMMU_SMMUV3_CONFIG_TRANSLATE:
		smmu_domain->s1_cfg.cdcfg.cdtab_dma = alloc->s1ctxptr;
		smmu_domain->s1_cfg.s1cdmax = alloc->s1cdmax;
		smmu_domain->s1_cfg.s1fmt = alloc->s1fmt;
		smmu_domain->bypass = false;
		smmu_domain->abort = false;
		break;
	default:
		break;
	}

	mutex_unlock(&smmu_domain->init_mutex);

	return domain;
}
