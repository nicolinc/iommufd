// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES.
 */
#include <linux/dma-buf.h>
#include <linux/pci-p2pdma.h>
#include <linux/dma-resv.h>

#include "vfio_pci_priv.h"

MODULE_IMPORT_NS("DMA_BUF");

struct vfio_pci_dma_buf {
	struct dma_buf *dmabuf;
	struct vfio_pci_core_device *vdev;
	struct list_head dmabufs_elm;
	size_t size;
	struct phys_vec *phys_vec;
	struct p2pdma_provider *provider;
	u32 nr_ranges;
	u8 revoked : 1;
};

struct vfio_pci_attach {
	struct dma_iova_state state;
	enum {
		VFIO_ATTACH_NONE,
		VFIO_ATTACH_HOST_BRIDGE_DMA,
		VFIO_ATTACH_HOST_BRIDGE_IOVA,
		VFIO_ATTACH_BUS
	} kind;
};

static int vfio_pci_dma_buf_attach(struct dma_buf *dmabuf,
				   struct dma_buf_attachment *attachment)
{
	struct vfio_pci_dma_buf *priv = dmabuf->priv;
	struct vfio_pci_attach *attach;

	if (!attachment->peer2peer)
		return -EOPNOTSUPP;

	if (priv->revoked)
		return -ENODEV;

	attach = kzalloc(sizeof(*attach), GFP_KERNEL);
	if (!attach)
		return -ENOMEM;
	attachment->priv = attach;

	switch (pci_p2pdma_map_type(priv->provider, attachment->dev)) {
	case PCI_P2PDMA_MAP_THRU_HOST_BRIDGE:
		if (dma_iova_try_alloc(attachment->dev, &attach->state, 0,
				       priv->size))
			attach->kind = VFIO_ATTACH_HOST_BRIDGE_IOVA;
		else
			attach->kind = VFIO_ATTACH_HOST_BRIDGE_DMA;
		return 0;
	case PCI_P2PDMA_MAP_BUS_ADDR:
		/* There is no need in IOVA at all for this flow. */
		attach->kind = VFIO_ATTACH_BUS;
		return 0;
	default:
		attach->kind = VFIO_ATTACH_NONE;
		return 0;
	}
	return 0;
}

static void vfio_pci_dma_buf_detach(struct dma_buf *dmabuf,
				    struct dma_buf_attachment *attachment)
{
	struct vfio_pci_attach *attach = attachment->priv;

	if (attach->kind == VFIO_ATTACH_HOST_BRIDGE_IOVA)
		dma_iova_free(attachment->dev, &attach->state);
	kfree(attach);
}

static struct scatterlist *fill_sg_entry(struct scatterlist *sgl, u64 length,
					 dma_addr_t addr)
{
	unsigned int len, nents;
	int i;

	nents = DIV_ROUND_UP(length, UINT_MAX);
	for (i = 0; i < nents; i++) {
		len = min_t(u64, length, UINT_MAX);
		length -= len;
		/*
		 * Follow the DMABUF rules for scatterlist, the struct page can
		 * be NULL'd for MMIO only memory.
		 */
		sg_set_page(sgl, NULL, len, 0);
		sg_dma_address(sgl) = addr + i * UINT_MAX;
		sg_dma_len(sgl) = len;
		sgl = sg_next(sgl);
	}

	return sgl;
}

static unsigned int calc_sg_nents(struct vfio_pci_dma_buf *priv,
				  struct vfio_pci_attach *attach)
{
	struct phys_vec *phys_vec = priv->phys_vec;
	unsigned int nents = 0;
	u32 i;

	if (attach->kind != VFIO_ATTACH_HOST_BRIDGE_IOVA) {
		for (i = 0; i < priv->nr_ranges; i++)
			nents += DIV_ROUND_UP(phys_vec[i].len, UINT_MAX);
	} else {
		/*
		 * In IOVA case, there is only one SG entry which spans
		 * for whole IOVA address space, but we need to make sure
		 * that it fits sg->length, maybe we need more.
		 */
		nents = DIV_ROUND_UP(priv->size, UINT_MAX);
	}

	return nents;
}

static struct sg_table *
vfio_pci_dma_buf_map(struct dma_buf_attachment *attachment,
		     enum dma_data_direction dir)
{
	struct vfio_pci_dma_buf *priv = attachment->dmabuf->priv;
	struct vfio_pci_attach *attach = attachment->priv;
	struct phys_vec *phys_vec = priv->phys_vec;
	unsigned long attrs = DMA_ATTR_MMIO;
	unsigned int nents, mapped_len = 0;
	struct scatterlist *sgl;
	struct sg_table *sgt;
	dma_addr_t addr;
	int ret;
	u32 i;

	dma_resv_assert_held(priv->dmabuf->resv);

	if (priv->revoked)
		return ERR_PTR(-ENODEV);

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	nents = calc_sg_nents(priv, attach);
	ret = sg_alloc_table(sgt, nents, GFP_KERNEL | __GFP_ZERO);
	if (ret)
		goto err_kfree_sgt;

	sgl = sgt->sgl;

	for (i = 0; i < priv->nr_ranges; i++) {
		switch (attach->kind) {
		case VFIO_ATTACH_BUS:
			addr = pci_p2pdma_bus_addr_map(priv->provider,
						       phys_vec[i].paddr);
			break;
		case VFIO_ATTACH_HOST_BRIDGE_IOVA:
			ret = dma_iova_link(attachment->dev, &attach->state,
					    phys_vec[i].paddr, 0,
					    phys_vec[i].len, dir, attrs);
			if (ret)
				goto err_unmap_dma;

			mapped_len += phys_vec[i].len;
			break;
		case VFIO_ATTACH_HOST_BRIDGE_DMA:
			addr = dma_map_phys(attachment->dev, phys_vec[i].paddr,
					    phys_vec[i].len, dir, attrs);
			ret = dma_mapping_error(attachment->dev, addr);
			if (ret)
				goto err_unmap_dma;
			break;
		default:
			ret = -EINVAL;
			goto err_unmap_dma;
		}

		if (attach->kind != VFIO_ATTACH_HOST_BRIDGE_IOVA)
			sgl = fill_sg_entry(sgl, phys_vec[i].len, addr);
	}

	if (attach->kind == VFIO_ATTACH_HOST_BRIDGE_IOVA) {
		WARN_ON_ONCE(mapped_len != priv->size);
		ret = dma_iova_sync(attachment->dev, &attach->state, 0, mapped_len);
		if (ret)
			goto err_unmap_dma;
		sgl = fill_sg_entry(sgl, mapped_len, attach->state.addr);
	}

	/*
	 * SGL must be NULL to indicate that SGL is the last one
	 * and we allocated correct number of entries in sg_alloc_table()
	 */
	WARN_ON_ONCE(sgl);
	return sgt;

err_unmap_dma:
	switch (attach->kind) {
	case VFIO_ATTACH_HOST_BRIDGE_IOVA:
		if (mapped_len)
			dma_iova_unlink(attachment->dev, &attach->state, 0,
					mapped_len, dir, attrs);
		break;
	case VFIO_ATTACH_HOST_BRIDGE_DMA:
		if (!i)
			break;
		for_each_sgtable_dma_sg(sgt, sgl, i)
			dma_unmap_phys(attachment->dev, sg_dma_address(sgl),
				       sg_dma_len(sgl), dir, attrs);
		break;
	default:
		break;
	}
	sg_free_table(sgt);
err_kfree_sgt:
	kfree(sgt);
	return ERR_PTR(ret);
}

static void vfio_pci_dma_buf_unmap(struct dma_buf_attachment *attachment,
				   struct sg_table *sgt,
				   enum dma_data_direction dir)
{
	struct vfio_pci_dma_buf *priv = attachment->dmabuf->priv;
	struct vfio_pci_attach *attach = attachment->priv;
	unsigned long attrs = DMA_ATTR_MMIO;
	struct scatterlist *sgl;
	int i;

	switch (attach->kind) {
	case VFIO_ATTACH_HOST_BRIDGE_IOVA:
		dma_iova_destroy(attachment->dev, &attach->state, priv->size,
				 dir, attrs);
		break;
	case VFIO_ATTACH_HOST_BRIDGE_DMA:
		for_each_sgtable_dma_sg(sgt, sgl, i)
			dma_unmap_phys(attachment->dev, sg_dma_address(sgl),
				       sg_dma_len(sgl), dir, attrs);
		break;
	default:
		break;
	}

	sg_free_table(sgt);
	kfree(sgt);
}

static void vfio_pci_dma_buf_release(struct dma_buf *dmabuf)
{
	struct vfio_pci_dma_buf *priv = dmabuf->priv;

	/*
	 * Either this or vfio_pci_dma_buf_cleanup() will remove from the list.
	 * The refcount prevents both.
	 */
	if (priv->vdev) {
		down_write(&priv->vdev->memory_lock);
		list_del_init(&priv->dmabufs_elm);
		up_write(&priv->vdev->memory_lock);
		vfio_device_put_registration(&priv->vdev->vdev);
	}
	kfree(priv->phys_vec);
	kfree(priv);
}

static const struct dma_buf_ops vfio_pci_dmabuf_ops = {
	.attach = vfio_pci_dma_buf_attach,
	.detach = vfio_pci_dma_buf_detach,
	.map_dma_buf = vfio_pci_dma_buf_map,
	.release = vfio_pci_dma_buf_release,
	.unmap_dma_buf = vfio_pci_dma_buf_unmap,
};

static int dma_ranges_to_p2p_phys(struct vfio_pci_dma_buf *priv,
				  struct vfio_device_feature_dma_buf *dma_buf,
				  struct vfio_region_dma_range *dma_ranges,
				  struct p2pdma_provider *provider)
{
	struct pci_dev *pdev = priv->vdev->pdev;
	phys_addr_t len = pci_resource_len(pdev, dma_buf->region_index);
	phys_addr_t pci_start;
	phys_addr_t pci_last;
	u32 i;

	if (!len)
		return -EINVAL;
	pci_start = pci_resource_start(pdev, dma_buf->region_index);
	pci_last = pci_start + len - 1;
	for (i = 0; i < dma_buf->nr_ranges; i++) {
		phys_addr_t last;

		if (!dma_ranges[i].length)
			return -EINVAL;

		if (check_add_overflow(pci_start, dma_ranges[i].offset,
				       &priv->phys_vec[i].paddr) ||
		    check_add_overflow(priv->phys_vec[i].paddr,
				       dma_ranges[i].length - 1, &last))
			return -EOVERFLOW;
		if (last > pci_last)
			return -EINVAL;

		priv->phys_vec[i].len = dma_ranges[i].length;
		priv->size += priv->phys_vec[i].len;
	}
	priv->nr_ranges = dma_buf->nr_ranges;
	priv->provider = provider;
	return 0;
}

static int validate_dmabuf_input(struct vfio_pci_core_device *vdev,
				 struct vfio_device_feature_dma_buf *dma_buf,
				 struct vfio_region_dma_range *dma_ranges,
				 struct p2pdma_provider **provider)
{
	u64 length = 0;
	u32 i;

	if (dma_buf->flags)
		return -EINVAL;
	/*
	 * For PCI the region_index is the BAR number like  everything else.
	 */
	if (dma_buf->region_index >= VFIO_PCI_ROM_REGION_INDEX)
		return -ENODEV;

	*provider = pcim_p2pdma_provider(vdev->pdev, dma_buf->region_index);
	if (!*provider)
		return -EINVAL;

	for (i = 0; i < dma_buf->nr_ranges; i++) {
		u64 offset = dma_ranges[i].offset;
		u64 len = dma_ranges[i].length;

		if (!len || !PAGE_ALIGNED(offset) || !PAGE_ALIGNED(len))
			return -EINVAL;

		if (check_add_overflow(length, len, &length))
			return -EINVAL;
	}

	/*
	 * DMA API uses size_t, so make sure that requested region length
	 * can fit into size_t variable, which can be unsigned int (32bits).
	 *
	 * In addition make sure that high bit of total length is not used too
	 * as it is used as a marker for DMA IOVA API.
	 */
	if (overflows_type(length, size_t) || length & DMA_IOVA_USE_SWIOTLB)
		return -EINVAL;

	return 0;
}

int vfio_pci_core_feature_dma_buf(struct vfio_pci_core_device *vdev, u32 flags,
				  struct vfio_device_feature_dma_buf __user *arg,
				  size_t argsz)
{
	struct vfio_device_feature_dma_buf get_dma_buf = {};
	struct vfio_region_dma_range *dma_ranges;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct p2pdma_provider *provider;
	struct vfio_pci_dma_buf *priv;
	int ret;

	ret = vfio_check_feature(flags, argsz, VFIO_DEVICE_FEATURE_GET,
				 sizeof(get_dma_buf));
	if (ret != 1)
		return ret;

	if (copy_from_user(&get_dma_buf, arg, sizeof(get_dma_buf)))
		return -EFAULT;

	if (!get_dma_buf.nr_ranges)
		return -EINVAL;

	dma_ranges = memdup_array_user(&arg->dma_ranges, get_dma_buf.nr_ranges,
				       sizeof(*dma_ranges));
	if (IS_ERR(dma_ranges))
		return PTR_ERR(dma_ranges);

	ret = validate_dmabuf_input(vdev, &get_dma_buf, dma_ranges, &provider);
	if (ret)
		goto err_free_ranges;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		ret = -ENOMEM;
		goto err_free_ranges;
	}
	priv->phys_vec = kcalloc(get_dma_buf.nr_ranges, sizeof(*priv->phys_vec),
				 GFP_KERNEL);
	if (!priv->phys_vec) {
		ret = -ENOMEM;
		goto err_free_priv;
	}

	priv->vdev = vdev;
	ret = dma_ranges_to_p2p_phys(priv, &get_dma_buf, dma_ranges,
				     provider);
	if (ret)
		goto err_free_phys;

	kfree(dma_ranges);
	dma_ranges = NULL;

	if (!vfio_device_try_get_registration(&vdev->vdev)) {
		ret = -ENODEV;
		goto err_free_phys;
	}

	exp_info.ops = &vfio_pci_dmabuf_ops;
	exp_info.size = priv->size;
	exp_info.flags = get_dma_buf.open_flags;
	exp_info.priv = priv;

	priv->dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(priv->dmabuf)) {
		ret = PTR_ERR(priv->dmabuf);
		goto err_dev_put;
	}

	/* dma_buf_put() now frees priv */
	INIT_LIST_HEAD(&priv->dmabufs_elm);
	down_write(&vdev->memory_lock);
	dma_resv_lock(priv->dmabuf->resv, NULL);
	priv->revoked = !__vfio_pci_memory_enabled(vdev);
	list_add_tail(&priv->dmabufs_elm, &vdev->dmabufs);
	dma_resv_unlock(priv->dmabuf->resv);
	up_write(&vdev->memory_lock);

	/*
	 * dma_buf_fd() consumes the reference, when the file closes the dmabuf
	 * will be released.
	 */
	return dma_buf_fd(priv->dmabuf, get_dma_buf.open_flags);

err_dev_put:
	vfio_device_put_registration(&vdev->vdev);
err_free_phys:
	kfree(priv->phys_vec);
err_free_priv:
	kfree(priv);
err_free_ranges:
	kfree(dma_ranges);
	return ret;
}

void vfio_pci_dma_buf_move(struct vfio_pci_core_device *vdev, bool revoked)
{
	struct vfio_pci_dma_buf *priv;
	struct vfio_pci_dma_buf *tmp;

	lockdep_assert_held_write(&vdev->memory_lock);

	list_for_each_entry_safe(priv, tmp, &vdev->dmabufs, dmabufs_elm) {
		if (!get_file_active(&priv->dmabuf->file))
			continue;

		if (priv->revoked != revoked) {
			dma_resv_lock(priv->dmabuf->resv, NULL);
			priv->revoked = revoked;
			dma_buf_move_notify(priv->dmabuf);
			dma_resv_unlock(priv->dmabuf->resv);
		}
		dma_buf_put(priv->dmabuf);
	}
}

void vfio_pci_dma_buf_cleanup(struct vfio_pci_core_device *vdev)
{
	struct vfio_pci_dma_buf *priv;
	struct vfio_pci_dma_buf *tmp;

	down_write(&vdev->memory_lock);
	list_for_each_entry_safe(priv, tmp, &vdev->dmabufs, dmabufs_elm) {
		if (!get_file_active(&priv->dmabuf->file))
			continue;

		dma_resv_lock(priv->dmabuf->resv, NULL);
		list_del_init(&priv->dmabufs_elm);
		priv->vdev = NULL;
		priv->revoked = true;
		dma_buf_move_notify(priv->dmabuf);
		dma_resv_unlock(priv->dmabuf->resv);
		vfio_device_put_registration(&vdev->vdev);
		dma_buf_put(priv->dmabuf);
	}
	up_write(&vdev->memory_lock);
}
