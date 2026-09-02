// SPDX-License-Identifier: GPL-2.0-only
/*
 * The physical regime: what the core does for a device that no IOMMU driver
 * translates for. In a confidential VM a device outside the trust boundary is
 * translated by the hypervisor, which the guest can neither see nor program,
 * so the IOMMU driver here is parked in its blocking domain and takes no part.
 *
 * Nothing else runs for such a device, so the core has to do the little that
 * it still needs, which today is turning on ATS for a device that requires it.
 */
#include <linux/pci.h>
#include <linux/pci-ats.h>

#include "iommu-priv.h"

/**
 * iommu_physical_regime_enter - Set up @dev to run outside its IOMMU
 * @dev: device entering the physical regime
 *
 * Called once the core has decided that no IOMMU driver will translate for
 * @dev. A device that cannot work without ATS keeps it on here, since the
 * driver that would otherwise enable it stays parked.
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
	 * The translation is done by something the guest cannot see, so there
	 * is no page size to match. Ask for the smallest unit the device can
	 * be given, which any translation granule is a multiple of.
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
