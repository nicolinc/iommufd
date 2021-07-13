// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2021-2024 NVIDIA CORPORATION & AFFILIATES. */

#define dev_fmt(fmt) "tegra241_cmdqv: " fmt

#include <linux/acpi.h>
#include <linux/debugfs.h>
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
#define TEGRA241_VINTF_PAGE_BASE	(TEGRA241_VCMDQ_PAGE1_BASE + SZ_64K)

/* CMDQV global config regs */
#define TEGRA241_CMDQV_CONFIG		0x0000
#define  CMDQV_EN			BIT(0)

#define TEGRA241_CMDQV_PARAM		0x0004
#define  CMDQV_NUM_VINTF_LOG2		GENMASK(11, 8)
#define  CMDQV_NUM_VCMDQ_LOG2		GENMASK(7, 4)

#define TEGRA241_CMDQV_STATUS		0x0008
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
#define TEGRA241_VINTFi_PAGE0(i)	(TEGRA241_VINTF_PAGE_BASE + SZ_128K*(i))
#define TEGRA241_VINTFi_PAGE1(i)	(TEGRA241_VINTFi_PAGE0(i) + SZ_64K)
#define TEGRA241_VINTFi_LVCMDQ_PAGE0(i, q) \
					(TEGRA241_VINTFi_PAGE0(i) + 0x80*(q))
#define TEGRA241_VINTFi_LVCMDQ_PAGE1(i, q) \
					(TEGRA241_VINTFi_PAGE1(i) + 0x80*(q))

/* MMIO helpers */
#define cmdqv_readl(reg) \
	readl(cmdqv->base + TEGRA241_CMDQV_##reg)
#define cmdqv_readl_relaxed(reg) \
	readl_relaxed(cmdqv->base + TEGRA241_CMDQV_##reg)
#define cmdqv_writel(val, reg) \
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
#define vcmdq_page1_readq_relaxed(reg) \
	readq_relaxed(vcmdq->page1 + TEGRA241_VCMDQ_##reg)
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
	dev_warn(cmdqv->dev, "CMDQV: " fmt, ##__VA_ARGS__)
#define cmdqv_err(fmt, ...) \
	dev_err(cmdqv->dev, "CMDQV: " fmt, ##__VA_ARGS__)
#define cmdqv_info(fmt, ...) \
	dev_info(cmdqv->dev, "CMDQV: " fmt, ##__VA_ARGS__)
#define cmdqv_dbg(fmt, ...) \
	dev_dbg(cmdqv->dev, "CMDQV: " fmt, ##__VA_ARGS__)

#define vintf_warn(fmt, ...) \
	dev_warn(vintf->cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)
#define vintf_err(fmt, ...) \
	dev_err(vintf->cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)
#define vintf_info(fmt, ...) \
	dev_info(vintf->cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)
#define vintf_dbg(fmt, ...) \
	dev_dbg(vintf->cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)

#define vcmdq_warn(fmt, ...)                                                   \
	({                                                                     \
		struct tegra241_vintf *vintf = vcmdq->vintf;                   \
		if (vintf)                                                     \
			vintf_warn("VCMDQ%u/LVCMDQ%u: " fmt,                   \
				   vcmdq->idx, vcmdq->lidx,                    \
				   ##__VA_ARGS__);                             \
		else                                                           \
			dev_warn(vcmdq->cmdqv->dev, "VCMDQ%u: " fmt,           \
				 vcmdq->idx, ##__VA_ARGS__);                   \
	})
#define vcmdq_err(fmt, ...)                                                    \
	({                                                                     \
		struct tegra241_vintf *vintf = vcmdq->vintf;                   \
		if (vintf)                                                     \
			vintf_err("VCMDQ%u/LVCMDQ%u: " fmt,                    \
				  vcmdq->idx, vcmdq->lidx,                     \
				  ##__VA_ARGS__);                              \
		else                                                           \
			dev_err(vcmdq->cmdqv->dev, "VCMDQ%u: " fmt,            \
				vcmdq->idx, ##__VA_ARGS__);                    \
	})
#define vcmdq_info(fmt, ...)                                                   \
	({                                                                     \
		struct tegra241_vintf *vintf = vcmdq->vintf;                   \
		if (vintf)                                                     \
			vintf_info("VCMDQ%u/LVCMDQ%u: " fmt,                   \
				   vcmdq->idx, vcmdq->lidx,                    \
				   ##__VA_ARGS__);                             \
		else                                                           \
			dev_info(vcmdq->cmdqv->dev, "VCMDQ%u: " fmt,           \
				 vcmdq->idx, ##__VA_ARGS__);                   \
	})
#define vcmdq_dbg(fmt, ...)                                                    \
	({                                                                     \
		struct tegra241_vintf *vintf = vcmdq->vintf;                   \
		if (vintf)                                                     \
			vintf_dbg("VCMDQ%u/LVCMDQ%u: " fmt,                    \
				  vcmdq->idx, vcmdq->lidx,                     \
				  ##__VA_ARGS__);                              \
		else                                                           \
			dev_dbg(vcmdq->cmdqv->dev, "VCMDQ%u: " fmt,            \
				vcmdq->idx, ##__VA_ARGS__);                    \
	})

/* Configuring and polling helpers */
#define tegra241_cmdqv_write_config(_owner, _OWNER, _regval)                   \
	({                                                                     \
		bool _en = (_regval) & _OWNER##_EN;                            \
		u32 _status;                                                   \
		int _ret;                                                      \
		writel((_regval), _owner->base + TEGRA241_##_OWNER##_CONFIG);  \
		_ret = readl_poll_timeout(                                     \
			_owner->base + TEGRA241_##_OWNER##_STATUS, _status,    \
			_en ? (_regval) & _OWNER##_ENABLED :                   \
			      !((_regval) & _OWNER##_ENABLED),                 \
			1, ARM_SMMU_POLL_TIMEOUT_US);                          \
		if (_ret)                                                      \
			_owner##_err("failed to %sable, STATUS = 0x%08X\n",    \
				     _en ? "en" : "dis", _status);             \
		_ret;                                                          \
	})

#define cmdqv_write_config(_regval) \
	tegra241_cmdqv_write_config(cmdqv, CMDQV, _regval)
#define vintf_write_config(_regval) \
	tegra241_cmdqv_write_config(vintf, VINTF, _regval)
#define vcmdq_write_config(_regval) \
	tegra241_cmdqv_write_config(vcmdq, VCMDQ, _regval)

static bool disable_cmdqv;
module_param(disable_cmdqv, bool, 0444);
MODULE_PARM_DESC(disable_cmdqv,
	"This allows to disable CMDQV HW and use default SMMU internal CMDQ.");

static bool bypass_vcmdq;
module_param(bypass_vcmdq, bool, 0444);
MODULE_PARM_DESC(bypass_vcmdq,
	"This allows to bypass VCMDQ for debugging use or perf comparison.");

/**
 * struct tegra241_vcmdq - Virtual Command Queue
 * @idx: Global index in the CMDQV HW
 * @lidx: Local index in the VINTF
 * @cmdqv: CMDQV HW pointer
 * @vintf: VINTF HW pointer
 * @cmdq: Command Queue struct
 * @base: MMIO base address
 * @page0: MMIO Page0 base address
 * @page1: MMIO Page1 base address
 */
struct tegra241_vcmdq {
	u16 idx;
	u16 lidx;

	struct tegra241_cmdqv *cmdqv;
	struct tegra241_vintf *vintf;
	struct arm_smmu_cmdq cmdq;

	void __iomem *base;
	void __iomem *page0;
	void __iomem *page1;
};

/**
 * struct tegra241_vintf - Virtual Interface
 * @idx: Global index in the CMDQV HW
 * @enabled: Enabled or not
 * @error: Status error or not
 * @cmdqv: CMDQV HW pointer
 * @vcmdqs: List of VCMDQ pointers
 * @base: MMIO base address
 */
struct tegra241_vintf {
	u16 idx;

	bool enabled;
	atomic_t error;	/* Race between interrupts and get_cmdq() */

	struct tegra241_cmdqv *cmdqv;
	struct tegra241_vcmdq **vcmdqs;

	void __iomem *base;
};

/**
 * struct tegra241_cmdqv - CMDQ-V for SMMUv3
 * @smmu: SMMUv3 pointer
 * @dev: Device pointer
 * @base: MMIO base address
 * @irq: IRQ number
 * @num_vintfs: Total number of VINTFs
 * @num_vcmdqs: Total number of VCMDQs
 * @num_vcmdqs_per_vintf: Number of VCMDQs per VINTF
 * @vintf_ids: VINTF id allocator
 * @vcmdq_ids: VCMDQ id allocator
 * @vtinfs: List of VINTFs
 */
struct tegra241_cmdqv {
	struct arm_smmu_device *smmu;

	struct device *dev;
	void __iomem *base;
	int irq;

	/* CMDQV Hardware Params */
	u16 num_vintfs;
	u16 num_vcmdqs;
	u16 num_vcmdqs_per_vintf;

	struct ida vintf_ids;
	struct ida vcmdq_ids;

	struct tegra241_vintf **vintfs;
};

static void tegra241_cmdqv_handle_vintf0_error(struct tegra241_cmdqv *cmdqv)
{
	struct tegra241_vintf *vintf = cmdqv->vintfs[0];
	int i;

	/* Cache error status to bypass VCMDQs until error is recovered */
	atomic_set(&vintf->error,
		   !!FIELD_GET(VINTF_STATUS, vintf_readl(STATUS)));

	for (i = 0; i < 4; i++) {
		u32 lvcmdq_err_map = vintf_readl_relaxed(CMDQ_ERR_MAP(i));

		while (lvcmdq_err_map) {
			int lidx = ffs(lvcmdq_err_map) - 1;
			struct tegra241_vcmdq *vcmdq = vintf->vcmdqs[lidx];
			u32 gerrorn, gerror;

			lvcmdq_err_map &= ~BIT(lidx);

			__arm_smmu_cmdq_skip_err(cmdqv->dev, &vcmdq->cmdq.q);

			gerrorn = vcmdq_page0_readl_relaxed(GERRORN);
			gerror = vcmdq_page0_readl_relaxed(GERROR);

			vcmdq_page0_writel(gerror, GERRORN);
		}
	}

	/* Now error status should be clean, cache it again */
	atomic_set(&vintf->error,
		   !!FIELD_GET(VINTF_STATUS, vintf_readl(STATUS)));
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

struct arm_smmu_cmdq *tegra241_cmdqv_get_cmdq(struct arm_smmu_device *smmu)
{
	struct tegra241_cmdqv *cmdqv = smmu->tegra241_cmdqv;
	struct tegra241_vintf *vintf = cmdqv->vintfs[0];
	u16 lidx;

	if (bypass_vcmdq)
		return &smmu->cmdq;

	/* Use SMMU CMDQ if vintfs[0] is uninitialized */
	if (!vintf->enabled)
		return &smmu->cmdq;

	/* Use SMMU CMDQ if vintfs[0] has error status */
	if (atomic_read(&vintf->error))
		return &smmu->cmdq;

	/*
	 * Select a vcmdq to use. Here we use a temporal solution to
	 * balance out traffic on cmdq issuing: each cmdq has its own
	 * lock, if all cpus issue cmdlist using the same cmdq, only
	 * one CPU at a time can enter the process, while the others
	 * will be spinning at the same lock.
	 */
	lidx = smp_processor_id() % cmdqv->num_vcmdqs_per_vintf;
	return &vintf->vcmdqs[lidx]->cmdq;
}

static void tegra241_vcmdq_hw_deinit(struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_cmdqv *cmdqv = vcmdq->cmdqv;

	if (vcmdq_write_config(0)) {
		vcmdq_err("GERRORN=0x%X\n", vcmdq_page0_readl_relaxed(GERRORN));
		vcmdq_err("GERROR=0x%X\n", vcmdq_page0_readl_relaxed(GERROR));
		vcmdq_err("CONS=0x%X\n", vcmdq_page0_readl_relaxed(CONS));
	}
	vcmdq_page0_writel_relaxed(0, PROD);
	vcmdq_page0_writel_relaxed(0, CONS);
	vcmdq_page1_writeq_relaxed(0, BASE);
	vcmdq_page1_writeq_relaxed(0, CONS_INDX_BASE);

	cmdqv_writel_relaxed(0, CMDQ_ALLOC(vcmdq->idx));
	vcmdq_dbg("deinited\n");
}

static int tegra241_vcmdq_hw_init(struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_cmdqv *cmdqv = vcmdq->cmdqv;
	struct tegra241_vintf *vintf = vcmdq->vintf;
	u32 regval;
	int ret;

	/* Configure and enable the vcmdq */
	tegra241_vcmdq_hw_deinit(vcmdq);

	regval  = FIELD_PREP(CMDQV_CMDQ_ALLOC_VINTF, vintf->idx);
	regval |= FIELD_PREP(CMDQV_CMDQ_ALLOC_LVCMDQ, vcmdq->lidx);
	regval |= CMDQV_CMDQ_ALLOCATED;
	cmdqv_writel_relaxed(regval, CMDQ_ALLOC(vcmdq->idx));

	vcmdq_page1_writeq_relaxed(vcmdq->cmdq.q.q_base, BASE);

	ret = vcmdq_write_config(VCMDQ_EN);
	if (ret) {
		vcmdq_err("GERRORN=0x%X\n", vcmdq_page0_readl_relaxed(GERRORN));
		vcmdq_err("GERROR=0x%X\n", vcmdq_page0_readl_relaxed(GERROR));
		vcmdq_err("CONS=0x%X\n", vcmdq_page0_readl_relaxed(CONS));
		return ret;
	}

	vcmdq_dbg("inited\n");
	return 0;
}

/* Adapt struct arm_smmu_cmdq init sequences from arm-smmu-v3.c for VCMDQs */
static int tegra241_vcmdq_alloc_smmu_cmdq(struct tegra241_vcmdq *vcmdq)
{
	struct arm_smmu_device *smmu = vcmdq->cmdqv->smmu;
	struct arm_smmu_cmdq *cmdq = &vcmdq->cmdq;
	struct arm_smmu_queue *q = &cmdq->q;
	char name[16];
	int ret;

	sprintf(name, "vcmdq%u", vcmdq->idx);

	q->llq.max_n_shift = ilog2(SZ_64K >> CMDQ_ENT_SZ_SHIFT);

	/* Use the common helper to init the VCMDQ, and then... */
	ret = arm_smmu_init_one_queue(smmu, q, vcmdq->page0,
				      TEGRA241_VCMDQ_PROD, TEGRA241_VCMDQ_CONS,
				      CMDQ_ENT_DWORDS, name);
	if (ret)
		return ret;

	/* ...override q_base to write VCMDQ_BASE registers */
	q->q_base = q->base_dma & VCMDQ_ADDR;
	q->q_base |= FIELD_PREP(VCMDQ_LOG2SIZE, q->llq.max_n_shift);

	/* All VCMDQs support CS_NONE only for CMD_SYNC */
	q->quirks = CMDQ_QUIRK_SYNC_CS_NONE_ONLY;

	return arm_smmu_cmdq_init(smmu, cmdq);
}

static void tegra241_vcmdq_free_smmu_cmdq(struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_cmdqv *cmdqv = vcmdq->cmdqv;
	struct arm_smmu_queue *q = &vcmdq->cmdq.q;
	size_t nents = 1 << q->llq.max_n_shift;

	dmam_free_coherent(cmdqv->smmu->dev, (nents * CMDQ_ENT_DWORDS) << 3,
			   q->base, q->base_dma);
}

static int tegra241_vintf_lvcmdq_init(struct tegra241_vintf *vintf, u16 lidx,
				      struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_cmdqv *cmdqv = vintf->cmdqv;
	u16 qidx;

	qidx = ida_alloc_max(&cmdqv->vcmdq_ids,
			     cmdqv->num_vcmdqs - 1, GFP_KERNEL);
	if (qidx < 0)
		return qidx;

	vcmdq->idx = qidx;
	vcmdq->lidx = lidx;
	vcmdq->cmdqv = cmdqv;
	vcmdq->vintf = vintf;
	vcmdq->page0 = cmdqv->base + TEGRA241_VCMDQ_PAGE0(qidx);
	vcmdq->page1 = cmdqv->base + TEGRA241_VCMDQ_PAGE1(qidx);
	vcmdq->base = vcmdq->page0; /* CONFIG register is in page0 */
	return 0;
}

static void tegra241_vintf_lvcmdq_deinit(struct tegra241_vcmdq *vcmdq)
{
	ida_free(&vcmdq->cmdqv->vcmdq_ids, vcmdq->idx);
}

static struct tegra241_vcmdq *
tegra241_vintf_lvcmdq_alloc(struct tegra241_vintf *vintf, u16 lidx)
{
	struct tegra241_cmdqv *cmdqv = vintf->cmdqv;
	struct tegra241_vcmdq *vcmdq;
	int ret;

	vcmdq = devm_kzalloc(cmdqv->dev, sizeof(*vcmdq), GFP_KERNEL);
	if (!vcmdq)
		return ERR_PTR(-ENOMEM);

	ret = tegra241_vintf_lvcmdq_init(vintf, lidx, vcmdq);
	if (ret)
		goto free_vcmdq;

	/* Setup struct arm_smmu_cmdq data members */
	ret = tegra241_vcmdq_alloc_smmu_cmdq(vcmdq);
	if (ret)
		goto deinit_lvcmdq;

	ret = tegra241_vcmdq_hw_init(vcmdq);
	if (ret)
		goto free_queue;

	vcmdq_dbg("allocated\n");
	return vcmdq;
free_queue:
	tegra241_vcmdq_free_smmu_cmdq(vcmdq);
deinit_lvcmdq:
	tegra241_vintf_lvcmdq_deinit(vcmdq);
free_vcmdq:
	devm_kfree(cmdqv->dev, vcmdq);
	return ERR_PTR(ret);
}

static void tegra241_vintf_lvcmdq_free(struct tegra241_vcmdq *vcmdq)
{
	tegra241_vcmdq_hw_deinit(vcmdq);
	tegra241_vcmdq_free_smmu_cmdq(vcmdq);
	tegra241_vintf_lvcmdq_deinit(vcmdq);
	devm_kfree(vcmdq->cmdqv->dev, vcmdq);
}

int tegra241_cmdqv_device_reset(struct arm_smmu_device *smmu)
{
	struct tegra241_cmdqv *cmdqv = smmu->tegra241_cmdqv;
	struct tegra241_vintf *vintf = cmdqv->vintfs[0];
	u32 regval;
	int lidx;
	int ret;

	/* Reset CMDQV */
	regval = cmdqv_readl_relaxed(CONFIG);
	ret = cmdqv_write_config(regval & ~CMDQV_EN);
	if (ret)
		return ret;
	ret = cmdqv_write_config(regval | CMDQV_EN);
	if (ret)
		return ret;

	/* Reset and configure vintf0 */
	ret = vintf_write_config(0);
	if (ret)
		return ret;

	regval = FIELD_PREP(VINTF_HYP_OWN, 1);
	vintf_writel(regval, CONFIG);

	ret = vintf_write_config(regval | VINTF_EN);
	if (ret)
		return ret;

	vintf->enabled = !!(VINTF_ENABLED & vintf_readl(STATUS));
	atomic_set(&vintf->error,
		   !!FIELD_GET(VINTF_STATUS, vintf_readl(STATUS)));

	/* Build an arm_smmu_cmdq for each vcmdq allocated to vintf */
	vintf->vcmdqs = devm_kcalloc(cmdqv->dev, cmdqv->num_vcmdqs_per_vintf,
				     sizeof(*vintf->vcmdqs), GFP_KERNEL);
	if (!vintf->vcmdqs)
		return -ENOMEM;

	/* Allocate logical vcmdqs to vintf */
	for (lidx = 0; lidx < cmdqv->num_vcmdqs_per_vintf; lidx++) {
		struct tegra241_vcmdq *vcmdq;

		vcmdq = tegra241_vintf_lvcmdq_alloc(vintf, lidx);
		if (IS_ERR(vcmdq))
			goto free_lvcmdq;
		vintf->vcmdqs[lidx] = vcmdq;
	}

	return 0;
free_lvcmdq:
	for (lidx--; lidx >= 0; lidx--)
		tegra241_vintf_lvcmdq_free(vintf->vcmdqs[lidx]);
	devm_kfree(cmdqv->dev, vintf->vcmdqs);
	return ret;
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
	adev = acpi_dev_get_first_match_dev(TEGRA241_CMDQV_HID, match_uid, -1);
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

struct dentry *cmdqv_debugfs_dir;

static int tegra241_cmdqv_probe(struct tegra241_cmdqv *cmdqv)
{
	struct tegra241_vintf *vintf;
	u32 regval;
	int ret;

	regval = cmdqv_readl(CONFIG);
	if (disable_cmdqv) {
		cmdqv_info("disable_cmdqv=true. Falling back to SMMU CMDQ\n");
		cmdqv_write_config(regval & ~CMDQV_EN);
		return -ENODEV;
	}

	ret = cmdqv_write_config(regval | CMDQV_EN);
	if (ret)
		return ret;

	regval = cmdqv_readl_relaxed(PARAM);
	cmdqv->num_vintfs = 1 << FIELD_GET(CMDQV_NUM_VINTF_LOG2, regval);
	cmdqv->num_vcmdqs = 1 << FIELD_GET(CMDQV_NUM_VCMDQ_LOG2, regval);
	cmdqv->num_vcmdqs_per_vintf = cmdqv->num_vcmdqs / cmdqv->num_vintfs;

	cmdqv->vintfs = devm_kcalloc(cmdqv->dev, cmdqv->num_vintfs,
				     sizeof(*cmdqv->vintfs), GFP_KERNEL);
	if (!cmdqv->vintfs)
		return -ENOMEM;

	vintf = devm_kzalloc(cmdqv->dev, sizeof(*vintf), GFP_KERNEL);
	if (!vintf) {
		ret = -ENOMEM;
		goto free_vintfs;
	}

	ida_init(&cmdqv->vintf_ids);
	ida_init(&cmdqv->vcmdq_ids);

	/* Reserve vintfs[0] for in-kernel use */
	ret = ida_alloc_max(&cmdqv->vintf_ids, 0, GFP_KERNEL);
	if (ret != 0) {
		cmdqv_err("failed to reserve vintf0: ret %d\n", ret);
		if (ret > 0)
			ret = -EBUSY;
		goto destroy_ids;
	}
	vintf->idx = 0;
	cmdqv->vintfs[0] = vintf;

	vintf->cmdqv = cmdqv;
	vintf->base = cmdqv->base + TEGRA241_VINTF(0);

#ifdef CONFIG_IOMMU_DEBUGFS
	if (!cmdqv_debugfs_dir) {
		cmdqv_debugfs_dir = debugfs_create_dir("tegra241_cmdqv", iommu_debugfs_dir);
		debugfs_create_bool("bypass_vcmdq", 0644, cmdqv_debugfs_dir, &bypass_vcmdq);
	}
#endif

	return 0;
destroy_ids:
	ida_destroy(&cmdqv->vcmdq_ids);
	ida_destroy(&cmdqv->vintf_ids);
	devm_kfree(cmdqv->dev, vintf);
free_vintfs:
	devm_kfree(cmdqv->dev, cmdqv->vintfs);
	return ret;
}

struct tegra241_cmdqv *
tegra241_cmdqv_acpi_probe(struct arm_smmu_device *smmu, int id)
{
	struct tegra241_cmdqv *cmdqv;

	cmdqv = tegra241_cmdqv_find_resource(smmu, id);
	if (!cmdqv)
		return NULL;

	if (tegra241_cmdqv_probe(cmdqv)) {
		if (cmdqv->irq > 0)
			devm_free_irq(smmu->dev, cmdqv->irq, cmdqv);
		devm_iounmap(smmu->dev, cmdqv->base);
		devm_kfree(smmu->dev, cmdqv);
		return NULL;
	}

	return cmdqv;
}
