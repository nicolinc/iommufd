// SPDX-License-Identifier: GPL-2.0-only
/*
 * A device in TDISP T=0 remains associated with its guest IOMMU, although the
 * IOMMU does not translate its DMA, which leaves the device outside the guest
 * trust boundary while TDISP remains T=0:
 *
 *   [device: T=0] ===> [hypervisor] ===> [memory]
 *       |
 *       +-- (guest association) --> [confidential IOMMU: blocking DMA]
 *
 * The IOMMU driver probes the device and retains its firmware association, but
 * blocks it while TDISP is T=0. The IOMMU core owns operations it still needs
 * to function.
 */
#include <linux/pci.h>
#include <linux/pci-ats.h>

#include "iommu-priv.h"

/**
 * iommu_tdisp_enter_t0 - Prepare @dev while TDISP is T=0
 * @dev: device entering TDISP T=0
 *
 * The IOMMU core invokes this helper after the driver marks @dev as TDISP T=0.
 * The device remains associated with its IOMMU while the core owns operations
 * required in this state. Enable ATS here when the device requires it and its
 * IOMMU driver therefore does not.
 */
int iommu_tdisp_enter_t0(struct device *dev)
{
	struct pci_dev *pdev;

	if (!dev_is_pci(dev))
		return 0;

	pdev = to_pci_dev(dev);
	if (!pci_ats_required(pdev))
		return 0;

	return pci_enable_ats(pdev, PCI_ATS_MIN_STU);
}

/**
 * iommu_tdisp_exit_t0 - Undo iommu_tdisp_enter_t0()
 * @dev: device leaving TDISP T=0
 */
void iommu_tdisp_exit_t0(struct device *dev)
{
	struct pci_dev *pdev;

	if (!dev_is_pci(dev))
		return;

	pdev = to_pci_dev(dev);
	if (pci_ats_required(pdev) && pdev->ats_enabled)
		pci_disable_ats(pdev);
}
