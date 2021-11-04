// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2021-2024 TEGRA241 CORPORATION & AFFILIATES */

#define dev_fmt(fmt) "tegra241_cmdqv: " fmt

#include <linux/acpi.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>

#include <acpi/acpixf.h>

#include "arm-smmu-v3.h"

#define TEGRA241_CMDQV_HID		"NVDA200C"

/* CMDQV register page base and size defines */
#define TEGRA241_CMDQV_CONFIG_BASE	(0)
#define TEGRA241_CMDQV_CONFIG_SIZE	(SZ_64K)
#define TEGRA241_VCMDQ_PAGE0_BASE	(TEGRA241_CMDQV_CONFIG_BASE + SZ_64K)
#define TEGRA241_VCMDQ_PAGE1_BASE	(TEGRA241_VCMDQ_PAGE0_BASE + SZ_64K)
#define TEGRA241_VINTF_VCMDQ_BASE	(TEGRA241_VCMDQ_PAGE1_BASE + SZ_64K)

/* CMDQV global config regs */
#define TEGRA241_CMDQV_CONFIG		0x0000
#define  CMDQV_EN			BIT(0)

#define TEGRA241_CMDQV_PARAM		0x0004
#define  CMDQV_NUM_VINTF_LOG2		GENMASK(11, 8)
#define  CMDQV_NUM_VCMDQ_LOG2		GENMASK(7, 4)

#define TEGRA241_CMDQV_STATUS		0x0008
#define  CMDQV_STATUS			GENMASK(2, 1)
#define  CMDQV_ENABLED			BIT(0)

#define TEGRA241_CMDQV_VINTF_ERR_MAP	0x0014
#define TEGRA241_CMDQV_VINTF_INT_MASK	0x001C
#define TEGRA241_CMDQV_VCMDQ_ERR_MAP0	0x0024
#define TEGRA241_CMDQV_VCMDQ_ERR_MAP(i)	(0x0024 + 0x4*(i))

#define TEGRA241_CMDQV_CMDQ_ALLOC(q)	(0x0200 + 0x4*(q))
#define  CMDQV_CMDQ_ALLOC_VINTF		GENMASK(20, 15)
#define  CMDQV_CMDQ_ALLOC_LVCMDQ	GENMASK(7, 1)
#define  CMDQV_CMDQ_ALLOCATED		BIT(0)

/* VINTF config regs */
#define TEGRA241_VINTF(v)		(0x1000 + 0x100*(v))

#define TEGRA241_VINTF_CONFIG		0x0000
#define  VINTF_HYP_OWN			BIT(17)
#define  VINTF_VMID			GENMASK(16, 1)
#define  VINTF_EN			BIT(0)

#define TEGRA241_VINTF_STATUS		0x0004
#define  VINTF_STATUS			GENMASK(3, 1)
#define  VINTF_ENABLED			BIT(0)

#define TEGRA241_VINTF_CMDQ_ERR_MAP(m)	(0x00C0 + 0x4*(m))

/* VCMDQ config regs */
/* -- PAGE0 -- */
#define TEGRA241_VCMDQ_PAGE0(q)		(TEGRA241_VCMDQ_PAGE0_BASE + 0x80*(q))

#define TEGRA241_VCMDQ_CONS		0x00000
#define  VCMDQ_CONS_ERR			GENMASK(30, 24)

#define TEGRA241_VCMDQ_PROD		0x00004

#define TEGRA241_VCMDQ_CONFIG		0x00008
#define  VCMDQ_EN			BIT(0)

#define TEGRA241_VCMDQ_STATUS		0x0000C
#define  VCMDQ_ENABLED			BIT(0)

#define TEGRA241_VCMDQ_GERROR		0x00010
#define TEGRA241_VCMDQ_GERRORN		0x00014

/* -- PAGE1 -- */
#define TEGRA241_VCMDQ_PAGE1(q)		(TEGRA241_VCMDQ_PAGE1_BASE + 0x80*(q))
#define  VCMDQ_ADDR			GENMASK(47, 5)
#define  VCMDQ_LOG2SIZE			GENMASK(4, 0)

#define TEGRA241_VCMDQ_BASE		0x00000
#define TEGRA241_VCMDQ_CONS_INDX_BASE	0x00008

/* VINTF logical-VCMDQ pages */
#define TEGRA241_VINTFi_PAGE0(i)	(TEGRA241_VINTF_VCMDQ_BASE + SZ_128K*(i))
#define TEGRA241_VINTFi_PAGE1(i)	(TEGRA241_VINTFi_PAGE0(i) + SZ_64K)
#define TEGRA241_VINTFi_VCMDQ_PAGE0(i, q) \
					(TEGRA241_VINTFi_PAGE0(i) + 0x80*(q))
#define TEGRA241_VINTFi_VCMDQ_PAGE1(i, q) \
					(TEGRA241_VINTFi_PAGE1(i) + 0x80*(q))

/* MMIO helpers */
#define cmdqv_readl(reg) \
	readl(cmdqv->base + TEGRA241_CMDQV_##reg)
#define cmdqv_readl_relaxed(reg) \
	readl_relaxed(cmdqv->base + TEGRA241_CMDQV_##reg)
#define cmdqv_write(val, reg) \
	writel((val), cmdqv->base + TEGRA241_CMDQV_##reg)
#define cmdqv_writel_relaxed(val, reg) \
	writel_relaxed((val), cmdqv->base + TEGRA241_CMDQV_##reg)

#define vintf_readl(reg) \
	readl(vintf->base + TEGRA241_VINTF_##reg)
#define vintf_readl_relaxed(reg) \
	readl_relaxed(vintf->base + TEGRA241_VINTF_##reg)
#define vintf_writel(val, reg) \
	writel((val), vintf->base + TEGRA241_VINTF_##reg)
#define vintf_writel_relaxed(val, reg) \
	writel_relaxed((val), vintf->base + TEGRA241_VINTF_##reg)

#define vcmdq_page0_readl(reg) \
	readl(vcmdq->page0 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page0_readl_relaxed(reg) \
	readl_relaxed(vcmdq->page0 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page0_writel(val, reg) \
	writel((val), vcmdq->page0 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page0_writel_relaxed(val, reg) \
	writel_relaxed((val), vcmdq->page0 + TEGRA241_VCMDQ_##reg)

#define vcmdq_page1_readl(reg) \
	readl(vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_readl_relaxed(reg) \
	readl_relaxed(vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writel(val, reg) \
	writel((val), vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writel_relaxed(val, reg) \
	writel_relaxed((val), vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writeq(val, reg) \
	writeq((val), vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writeq_relaxed(val, reg) \
	writeq_relaxed((val), vcmdq->page1 + TEGRA241_VCMDQ_##reg)

/* Logging helpers */
#define cmdqv_warn(fmt, ...) \
	dev_warn(cmdqv->dev, fmt, ##__VA_ARGS__)
#define cmdqv_err(fmt, ...) \
	dev_err(cmdqv->dev, fmt, ##__VA_ARGS__)
#define cmdqv_info(fmt, ...) \
	dev_info(cmdqv->dev, fmt, ##__VA_ARGS__)
#define cmdqv_dbg(fmt, ...) \
	dev_dbg(cmdqv->dev, fmt, ##__VA_ARGS__)

#define vintf_warn(fmt, ...) \
	dev_warn(cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)
#define vintf_err(fmt, ...) \
	dev_err(cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)
#define vintf_info(fmt, ...) \
	dev_info(cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)
#define vintf_dbg(fmt, ...) \
	dev_dbg(cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)

#define vcmdq_warn(fmt, ...)                                       \
	do {                                                       \
		if (vcmdq->vintf)                                  \
			vintf_warn("VCMDQ%u/LVCMDQ%u: " fmt,       \
				   vcmdq->idx, vcmdq->logical_idx, \
				   ##__VA_ARGS__);                 \
		else                                               \
			dev_warn(cmdqv->dev, "VCMDQ%u: " fmt,      \
				 vcmdq->idx, ##__VA_ARGS__);       \
	} while (0)
#define vcmdq_err(fmt, ...)                                        \
	do {                                                       \
		if (vcmdq->vintf)                                  \
			vintf_err("VCMDQ%u/LVCMDQ%u: " fmt,        \
				  vcmdq->idx, vcmdq->logical_idx,  \
				  ##__VA_ARGS__);                  \
		else                                               \
			dev_err(cmdqv->dev, "VCMDQ%u: " fmt,       \
				vcmdq->idx, ##__VA_ARGS__);        \
	} while (0)
#define vcmdq_info(fmt, ...)                                       \
	do {                                                       \
		if (vcmdq->vintf)                                  \
			vintf_info("VCMDQ%u/LVCMDQ%u: " fmt,       \
				   vcmdq->idx, vcmdq->logical_idx, \
				   ##__VA_ARGS__);                 \
		else                                               \
			dev_info(cmdqv->dev, "VCMDQ%u: " fmt,      \
				 vcmdq->idx, ##__VA_ARGS__);       \
	} while (0)
#define vcmdq_dbg(fmt, ...)                                        \
	do {                                                       \
		if (vcmdq->vintf)                                  \
			vintf_dbg("VCMDQ%u/LVCMDQ%u: " fmt,        \
				  vcmdq->idx, vcmdq->logical_idx,  \
				  ##__VA_ARGS__);                  \
		else                                               \
			dev_dbg(cmdqv->dev, "VCMDQ%u: " fmt,       \
				vcmdq->idx, ##__VA_ARGS__);        \
	} while (0)

static bool disable_cmdqv;
module_param(disable_cmdqv, bool, 0444);
MODULE_PARM_DESC(disable_cmdqv,
	"This allows to disable CMDQV and use default SMMU internal CMDQ.");

struct tegra241_vcmdq {
	u16 idx;
	u16 logical_idx;

	struct arm_smmu_cmdq cmdq;
	struct tegra241_vintf *vintf;

	void __iomem *page0;
	void __iomem *page1;
};

struct tegra241_vintf {
	u16 idx;
	u32 cfg;
	u32 status;

	void __iomem *base;
	struct tegra241_cmdqv *cmdqv;
	struct tegra241_vcmdq **vcmdqs;
};

struct tegra241_cmdqv {
	struct arm_smmu_device *smmu;

	struct device *dev;
	struct resource res;
	void __iomem *base;
	int irq;

	/* CMDQV Hardware Params */
	u16 num_total_vintfs;
	u16 num_total_vcmdqs;
	u16 num_vcmdqs_per_vintf;

	struct xarray vcmdqs;
	struct xarray vintfs;
	struct tegra241_vintf **vintf;
};

static void tegra241_cmdqv_handle_vintf0_error(struct tegra241_cmdqv *cmdqv)
{
	struct tegra241_vintf *vintf = cmdqv->vintf[0];
	int i;

	/* Cache error status to bypass VCMDQs until error is recovered */
	vintf->status = vintf_readl_relaxed(STATUS);

	for (i = 0; i < 4; i++) {
		u32 lvcmdq_err_map = vintf_readl_relaxed(CMDQ_ERR_MAP(i));

		while (lvcmdq_err_map) {
			int qidx = ffs(lvcmdq_err_map) - 1;
			struct tegra241_vcmdq *vcmdq = vintf->vcmdqs[qidx];
			u32 gerrorn, gerror;

			lvcmdq_err_map &= ~BIT(qidx);

			__arm_smmu_cmdq_skip_err(cmdqv->dev, &vcmdq->cmdq.q);

			gerrorn = vcmdq_page0_readl_relaxed(GERRORN);
			gerror = vcmdq_page0_readl_relaxed(GERROR);
			vcmdq_page0_writel(gerror, GERRORN);
		}
	}

	/* Now status should be clean, cache it again */
	vintf->status = vintf_readl_relaxed(STATUS);
}

static irqreturn_t tegra241_cmdqv_isr(int irq, void *devid)
{
	struct tegra241_cmdqv *cmdqv = (struct tegra241_cmdqv *)devid;
	u32 vintf_errs[2];
	u32 vcmdq_errs[4];

	vintf_errs[0] = cmdqv_readl_relaxed(VINTF_ERR_MAP);
	vintf_errs[1] = cmdqv_readl_relaxed(VINTF_ERR_MAP + 0x4);

	vcmdq_errs[0] = cmdqv_readl_relaxed(VCMDQ_ERR_MAP(0));
	vcmdq_errs[1] = cmdqv_readl_relaxed(VCMDQ_ERR_MAP(1));
	vcmdq_errs[2] = cmdqv_readl_relaxed(VCMDQ_ERR_MAP(2));
	vcmdq_errs[3] = cmdqv_readl_relaxed(VCMDQ_ERR_MAP(3));

	cmdqv_warn("unexpected cmdqv error reported\n");
	cmdqv_warn(" vintf_map: 0x%08X%08X\n", vintf_errs[1], vintf_errs[0]);
	cmdqv_warn(" vcmdq_map: 0x%08X%08X%08X%08X\n",
		   vcmdq_errs[3], vcmdq_errs[2], vcmdq_errs[1], vcmdq_errs[0]);

	/* Handle VINTF0 and its VCMDQs */
	if (vintf_errs[0] & 0x1)
		tegra241_cmdqv_handle_vintf0_error(cmdqv);

	return IRQ_HANDLED;
}

/* Adapt struct arm_smmu_cmdq init sequences from arm-smmu-v3.c for VCMDQs */
static int tegra241_cmdqv_init_one_vcmdq(struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_cmdqv *cmdqv = vcmdq->vintf->cmdqv;
	struct arm_smmu_cmdq *cmdq = &vcmdq->cmdq;
	struct arm_smmu_queue *q = &cmdq->q;
	char name[16];
	int ret;

	sprintf(name, "vcmdq%u", vcmdq->idx);

	q->llq.max_n_shift = ilog2(SZ_64K >> CMDQ_ENT_SZ_SHIFT);

	/* Use the common helper to init the VCMDQ, and then... */
	ret = arm_smmu_init_one_queue(cmdqv->smmu, q, vcmdq->page0,
				      TEGRA241_VCMDQ_PROD, TEGRA241_VCMDQ_CONS,
				      CMDQ_ENT_DWORDS, name);
	if (ret)
		return ret;

	/* ...override q_base to write VCMDQ_BASE registers */
	q->q_base  = q->base_dma & VCMDQ_ADDR;
	q->q_base |= FIELD_PREP(VCMDQ_LOG2SIZE, q->llq.max_n_shift);

	/* All VCMDQs support CS_NONE only for CMD_SYNC */
	q->quirks = CMDQ_QUIRK_SYNC_CS_NONE_ONLY;

	return arm_smmu_cmdq_init(cmdqv->smmu, cmdq);
}

static bool tegra241_vintf_support_cmds(struct tegra241_vintf *vintf,
					u64 *cmds, int n)
{
	int i;

	/* VINTF owned by hypervisor can execute any command */
	if (FIELD_GET(VINTF_HYP_OWN, vintf->cfg))
		return true;

	/* Guest-owned VINTF must Check against the list of supported CMDs */
	for (i = 0; i < n; i++) {
		switch (FIELD_GET(CMDQ_0_OP, cmds[i * CMDQ_ENT_DWORDS])) {
		case CMDQ_OP_TLBI_NH_ASID:
		case CMDQ_OP_TLBI_NH_VA:
		case CMDQ_OP_ATC_INV:
			continue;
		default:
			return false;
		}
	}

	return true;
}

struct arm_smmu_cmdq *tegra241_cmdqv_get_cmdq(struct arm_smmu_device *smmu,
					      u64 *cmds, int n)

{
	struct tegra241_cmdqv *cmdqv = smmu->tegra241_cmdqv;
	struct tegra241_vintf *vintf = cmdqv->vintf[0];
	u16 qidx;

	/* Use SMMU CMDQ if vintf[0] is uninitialized */
	if (!FIELD_GET(VINTF_ENABLED, vintf->status))
		return &smmu->cmdq;

	/* Use SMMU CMDQ if vintf[0] has error status */
	if (FIELD_GET(VINTF_STATUS, vintf->status))
		return &smmu->cmdq;

	/* Unsupported CMDs go for smmu->cmdq pathway */
	if (!tegra241_vintf_support_cmds(vintf, cmds, n))
		return &smmu->cmdq;

	/*
	 * Select a vcmdq to use. Here we use a temporal solution to
	 * balance out traffic on cmdq issuing: each cmdq has its own
	 * lock, if all cpus issue cmdlist using the same cmdq, only
	 * one CPU at a time can enter the process, while the others
	 * will be spinning at the same lock.
	 */
	qidx = smp_processor_id() % cmdqv->num_vcmdqs_per_vintf;
	return &vintf->vcmdqs[qidx]->cmdq;
}

static int tegra241_vintf0_init_vcmdq(struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_vintf *vintf = vcmdq->vintf;
	struct tegra241_cmdqv *cmdqv = vintf->cmdqv;
	u32 regval;
	int ret;

	/* Setup struct arm_smmu_cmdq data members */
	tegra241_cmdqv_init_one_vcmdq(vcmdq);

	/* Configure and enable the vcmdq */
	vcmdq_page0_writel_relaxed(0, PROD);
	vcmdq_page0_writel_relaxed(0, CONS);

	vcmdq_page1_writeq_relaxed(vcmdq->cmdq.q.q_base, BASE);
	vcmdq_page0_writel_relaxed(VCMDQ_EN, CONFIG);
	ret = readl_poll_timeout(vcmdq->page0 + TEGRA241_VCMDQ_STATUS,
				 regval, regval == VCMDQ_ENABLED,
				 1, ARM_SMMU_POLL_TIMEOUT_US);
	if (ret) {
		u32 gerror = vcmdq_page0_readl_relaxed(GERROR);
		u32 gerrorn = vcmdq_page0_readl_relaxed(GERRORN);
		u32 cons = vcmdq_page0_readl_relaxed(CONS);

		vcmdq_err("failed to enable\n");
		vcmdq_err("  GERROR=0x%X\n", gerror);
		vcmdq_err("  GERRORN=0x%X\n", gerrorn);
		vcmdq_err("  CONS=0x%X\n", cons);
		return ret;
	}

	vcmdq_info("inited\n");
	return 0;
}

int tegra241_cmdqv_device_reset(struct arm_smmu_device *smmu)
{
	struct tegra241_cmdqv *cmdqv = smmu->tegra241_cmdqv;
	struct tegra241_vintf *vintf = cmdqv->vintf[0];
	u32 regval;
	u16 qidx;
	int ret;

	/* Setup vintf[0] for host kernel */
	vintf->idx = 0;
	vintf->cmdqv = cmdqv;
	vintf->base = cmdqv->base + TEGRA241_VINTF(0);

	/*
	 * Note that HYP_OWN bit is wired to zero when running in guest kernel
	 * regardless of enabling it here, as !HYP_OWN cmdqs have a restricted
	 * set of supported commands, by following the HW design.
	 */
	regval = FIELD_PREP(VINTF_HYP_OWN, 1);
	vintf_writel(regval, CONFIG);

	regval |= FIELD_PREP(VINTF_EN, 1);
	vintf_writel(regval, CONFIG);

	/*
	 * As being mentioned above, HYP_OWN bit is wired to zero for a guest
	 * kernel, so read back regval from HW to ensure that reflects in cfg
	 */
	vintf->cfg = vintf_readl(CONFIG);

	ret = readl_relaxed_poll_timeout(vintf->base + TEGRA241_VINTF_STATUS,
					 regval, regval & VINTF_ENABLED,
					 1, ARM_SMMU_POLL_TIMEOUT_US);
	if (ret) {
		vintf_err("failed to enable: STATUS = 0x%08X\n", regval);
		return ret;
	}

	vintf->status = regval;

	/* Allocate vcmdqs to vintf */
	for (qidx = 0; qidx < cmdqv->num_vcmdqs_per_vintf; qidx++) {
		regval  = FIELD_PREP(CMDQV_CMDQ_ALLOC_VINTF, vintf->idx);
		regval |= FIELD_PREP(CMDQV_CMDQ_ALLOC_LVCMDQ, qidx);
		regval |= CMDQV_CMDQ_ALLOCATED;
		cmdqv_writel_relaxed(regval, CMDQ_ALLOC(qidx));
	}

	/* Build an arm_smmu_cmdq for each vcmdq allocated to vintf */
	vintf->vcmdqs = devm_kcalloc(cmdqv->dev, cmdqv->num_vcmdqs_per_vintf,
				     sizeof(*vintf->vcmdqs), GFP_KERNEL);
	if (!vintf->vcmdqs)
		return -ENOMEM;

	for (qidx = 0; qidx < cmdqv->num_vcmdqs_per_vintf; qidx++) {
		struct tegra241_vcmdq *vcmdq;

		vcmdq = devm_kzalloc(cmdqv->dev, sizeof(*vcmdq), GFP_KERNEL);
		if (!vcmdq)
			return -ENOMEM;
		vcmdq->vintf = vintf;
		vcmdq->idx = vcmdq->logical_idx = qidx;
		vcmdq->page0 = cmdqv->base + TEGRA241_VCMDQ_PAGE0(qidx);
		vcmdq->page1 = cmdqv->base + TEGRA241_VCMDQ_PAGE1(qidx);
		ret = tegra241_vintf0_init_vcmdq(vcmdq);
		if (ret)
			return ret;
		vintf->vcmdqs[qidx] = vcmdq;
	}

	/* Reserve vintf[0] for kernel and hypervisor use */
	xa_init_flags(&cmdqv->vintfs, XA_FLAGS_ALLOC1 | XA_FLAGS_ACCOUNT);
	xa_init_flags(&cmdqv->vcmdqs, XA_FLAGS_ALLOC | XA_FLAGS_ACCOUNT);

	if (cmdqv->vintf && cmdqv->vintf[0])
		cmdqv->vintf[0] = vintf;

	return 0;
}

static int tegra241_cmdqv_acpi_is_memory(struct acpi_resource *res, void *data)
{
	struct resource_win win;

	return !acpi_dev_resource_address_space(res, &win);
}

static int tegra241_cmdqv_acpi_get_irqs(struct acpi_resource *ares, void *data)
{
	struct resource r;
	int *irq = data;

	if (*irq <= 0 && acpi_dev_resource_interrupt(ares, 0, &r))
		*irq = r.start;

	return 1; /* No need to add resource to the list */
}

static struct tegra241_cmdqv *
tegra241_cmdqv_find_resource(struct arm_smmu_device *smmu, int id)
{
	struct tegra241_cmdqv *cmdqv = NULL;
	struct device *dev = smmu->dev;
	struct list_head resource_list;
	struct resource_entry *rentry;
	struct acpi_device *adev;
	const char *match_uid;
	int ret;

	if (acpi_disabled)
		return NULL;

	/* Look for a device in the DSDT whose _UID matches the SMMU node ID */
	match_uid = kasprintf(GFP_KERNEL, "%u", id);
	adev = acpi_dev_get_first_match_dev(TEGRA241_CMDQV_HID,
					    match_uid, -1);
	kfree(match_uid);

	if (!adev)
		return NULL;

	dev_info(dev, "found companion CMDQV device, %s\n",
		 dev_name(&adev->dev));

	INIT_LIST_HEAD(&resource_list);
	ret = acpi_dev_get_resources(adev, &resource_list,
				     tegra241_cmdqv_acpi_is_memory, NULL);
	if (ret < 0) {
		dev_err(dev, "failed to get memory resource: %d\n", ret);
		goto put_dev;
	}

	cmdqv = devm_kzalloc(dev, sizeof(*cmdqv), GFP_KERNEL);
	if (!cmdqv)
		goto free_list;

	cmdqv->dev = dev;
	cmdqv->smmu = smmu;

	rentry = list_first_entry_or_null(&resource_list,
					  struct resource_entry, node);
	if (!rentry) {
		cmdqv_err("failed to get memory resource entry\n");
		goto free_cmdqv;
	}

	cmdqv->res = *(rentry->res);

	cmdqv->base = devm_ioremap_resource(smmu->dev, rentry->res);
	if (IS_ERR(cmdqv->base)) {
		cmdqv_err("failed to ioremap: %ld\n", PTR_ERR(cmdqv->base));
		goto free_cmdqv;
	}

	acpi_dev_free_resource_list(&resource_list);

	INIT_LIST_HEAD(&resource_list);

	ret = acpi_dev_get_resources(adev, &resource_list,
				     tegra241_cmdqv_acpi_get_irqs, &cmdqv->irq);
	if (ret < 0 || cmdqv->irq <= 0) {
		cmdqv_warn("no cmdqv interrupt. errors will not be reported\n");
	} else {
		ret = devm_request_irq(smmu->dev, cmdqv->irq,
				       tegra241_cmdqv_isr, 0,
				       "tegra241-cmdqv", cmdqv);
		if (ret) {
			cmdqv_err("failed to request irq (%d): %d\n",
				  cmdqv->irq, ret);
			goto iounmap;
		}
	}

	goto free_list;

iounmap:
	devm_iounmap(cmdqv->dev, cmdqv->base);
free_cmdqv:
	devm_kfree(cmdqv->dev, cmdqv);
	cmdqv = NULL;
free_list:
	acpi_dev_free_resource_list(&resource_list);
put_dev:
	put_device(&adev->dev);

	return cmdqv;
}

struct tegra241_cmdqv *
tegra241_cmdqv_acpi_probe(struct arm_smmu_device *smmu, int id)
{
	struct tegra241_cmdqv *cmdqv;
	u32 regval;

	cmdqv = tegra241_cmdqv_find_resource(smmu, id);
	if (!cmdqv)
		return NULL;

	regval = cmdqv_readl_relaxed(CONFIG);
	if (disable_cmdqv) {
		cmdqv_info("disable_cmdqv=true. Falling back to SMMU CMDQ\n");
		cmdqv_writel_relaxed(regval & ~CMDQV_EN, CONFIG);
		goto free_res;
	}

	cmdqv_writel_relaxed(regval | CMDQV_EN, CONFIG);

	regval = cmdqv_readl_relaxed(STATUS);
	if (!FIELD_GET(CMDQV_ENABLED, regval) ||
	    FIELD_GET(CMDQV_STATUS, regval)) {
		cmdqv_err("CMDQV h/w not ready: CMDQV_STATUS=0x%08X\n", regval);
		goto free_res;
	}

	regval = cmdqv_readl_relaxed(PARAM);
	cmdqv->num_total_vintfs = 1 << FIELD_GET(CMDQV_NUM_VINTF_LOG2, regval);
	cmdqv->num_total_vcmdqs = 1 << FIELD_GET(CMDQV_NUM_VCMDQ_LOG2, regval);
	cmdqv->num_vcmdqs_per_vintf =
		cmdqv->num_total_vcmdqs / cmdqv->num_total_vintfs;

	cmdqv->vintf = devm_kcalloc(cmdqv->dev, cmdqv->num_total_vintfs,
				    sizeof(*cmdqv->vintf), GFP_KERNEL);
	if (!cmdqv->vintf)
		goto free_res;

	cmdqv->vintf[0] = devm_kzalloc(cmdqv->dev, sizeof(*(cmdqv->vintf[0])),
				       GFP_KERNEL);
	if (!cmdqv->vintf[0])
		goto free_vintf;

	return cmdqv;

free_vintf:
	devm_kfree(cmdqv->dev, cmdqv->vintf);
free_res:
	if (cmdqv->irq > 0)
		devm_free_irq(smmu->dev, cmdqv->irq, cmdqv);
	devm_iounmap(smmu->dev, cmdqv->base);
	devm_kfree(smmu->dev, cmdqv);

	return NULL;
}
