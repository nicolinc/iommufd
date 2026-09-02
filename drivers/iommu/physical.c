// SPDX-License-Identifier: GPL-2.0-only
/*
 * A device in the physical regime remains associated with the guest IOMMU, but
 * the guest IOMMU does not translate its DMA. For the confidential guest, this
 * state exists before the device enters the guest trust boundary:
 *
 *   [device] === (physical regime) ===> [hypervisor] ===> [memory]
 *       |
 *       +-- (guest association) --> [confidential IOMMU: blocking DMA]
 *
 * The IOMMU driver probes the device and retains its firmware association, but
 * blocks the devices that are in the physical regime. Thus, the physical regime
 * has to control some IOMMU related operations.
 */
#include <linux/pci.h>
#include <linux/pci-ats.h>

#include "iommu-priv.h"

/**
 * iommu_physical_regime_enter - Prepare @dev for the physical regime
 * @dev: device entering the physical regime
 *
 * The IOMMU core calls this helper after the driver marks @dev for the physical
 * regime. The device remains associated with its IOMMU while the core owns the
 * operations required by the physical regime. Enable ATS here when the device
 * requires it and its IOMMU driver therefore does not.
 */
int iommu_physical_regime_enter(struct device *dev)
{
	struct pci_dev *pdev;

	if (!dev_is_pci(dev))
		return 0;

	pdev = to_pci_dev(dev);
	if (!pci_ats_required(pdev))
		return 0;

	/*
	 * The guest cannot see the translation granule used within the physical
	 * regime, so request the smallest unit supported by the device because
	 * each translation granule is a multiple of it.
	 */
	return pci_enable_ats(pdev, PCI_ATS_MIN_STU);
}

/**
 * iommu_physical_regime_exit - Undo iommu_physical_regime_enter()
 * @dev: device leaving the physical regime
 */
void iommu_physical_regime_exit(struct device *dev)
{
	struct pci_dev *pdev;

	if (!dev_is_pci(dev))
		return;

	pdev = to_pci_dev(dev);
	if (pci_ats_required(pdev) && pdev->ats_enabled)
		pci_disable_ats(pdev);
}
