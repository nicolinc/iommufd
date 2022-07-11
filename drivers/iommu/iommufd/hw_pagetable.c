// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/circ_buf.h>

#include "iommufd_private.h"

static void
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable_s1 *s1);

void iommufd_hw_pagetable_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);

	WARN_ON(!xa_empty(&hwpt->devices));

	if (hwpt->obj.type == IOMMUFD_OBJ_HW_PAGETABLE) {
		struct iommufd_hw_pagetable_auto *auto_hwpt = &hwpt->auto_hwpt;

		refcount_dec(&auto_hwpt->ioas->obj.users);
	} else if (hwpt->obj.type == IOMMUFD_OBJ_HW_PAGETABLE_S1) {
		struct iommufd_hw_pagetable_s1 *s1_hwpt = &hwpt->s1_hwpt;

		refcount_dec(&s1_hwpt->stage2->obj.users);
	}

	iommu_domain_free(hwpt->domain);
	mutex_destroy(&hwpt->devices_lock);
}

/**
 * iommufd_hw_pagetable_alloc() - Get an iommu_domain for a device
 * @ictx: iommufd context
 * @ioas: IOAS to associate the domain with
 * @dev: Device to get an iommu_domain for
 *
 * Allocate a new iommu_domain and return it as a hw_pagetable.
 */
struct iommufd_hw_pagetable *
iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct iommufd_ioas *ioas,
			   struct device *dev)
{
	struct iommufd_hw_pagetable_auto *auto_hwpt;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	hwpt->domain = iommu_domain_alloc(dev->bus);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	xa_init_flags(&hwpt->devices, XA_FLAGS_ALLOC1 | XA_FLAGS_ACCOUNT);
	mutex_init(&hwpt->devices_lock);
	auto_hwpt = &hwpt->auto_hwpt;
	INIT_LIST_HEAD(&auto_hwpt->auto_domains_item);
	auto_hwpt->ioas = ioas;
	/* The calling driver is a user until the hw_pagetable is destroyed */
	refcount_inc(&ioas->obj.users);
	return hwpt;

out_abort:
	iommufd_object_abort(ictx, &hwpt->obj);
	return ERR_PTR(rc);
}

static int iommufd_hw_pagetable_eventfd_setup(struct eventfd_ctx **ctx, int fd)
{
	struct eventfd_ctx *efdctx;

	efdctx = eventfd_ctx_fdget(fd);
	if (IS_ERR(efdctx))
		return PTR_ERR(efdctx);
	if (*ctx)
		eventfd_ctx_put(*ctx);
	*ctx = efdctx;
	return 0;
}

static void iommufd_hw_pagetable_eventfd_destroy(struct eventfd_ctx **ctx)
{
	eventfd_ctx_put(*ctx);
	*ctx = NULL;
}

static ssize_t hwpt_fault_fops_read(struct file *filep, char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct iommufd_hw_pagetable_s1 *s1 = filep->private_data;
	loff_t pos = *ppos;
	void *base = s1->fault_pages;
	size_t size = s1->fault_region_size;
	int ret = -EFAULT;

	if (pos >= size)
		return -EINVAL;

	count = min(count, (size_t)(size - pos));

	mutex_lock(&s1->fault_queue_lock);
	if (!copy_to_user(buf, base + pos, count)) {
		*ppos += count;
		ret = count;
	}
	mutex_unlock(&s1->fault_queue_lock);

	return ret;
}

static ssize_t hwpt_fault_fops_write(struct file *filep,
				     const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct iommufd_hw_pagetable_s1 *s1 = filep->private_data;
	loff_t pos = *ppos;
	void *base = s1->fault_pages;
	struct iommufd_stage1_dma_fault *header =
			(struct iommufd_stage1_dma_fault *)base;
	size_t size = s1->fault_region_size;
	u32 new_tail;
	int ret = -EFAULT;

	if (pos >= size)
		return -EINVAL;

	count = min(count, (size_t)(size - pos));

	mutex_lock(&s1->fault_queue_lock);

	/* Only allows write to the tail which locates at offset 0 */
	if (pos != 0 || count != 4) {
		ret = -EINVAL;
		goto unlock;
	}

	if (copy_from_user((void *)&new_tail, buf, count))
		goto unlock;

	/* new tail should not exceed the maximum index */
	if (new_tail > header->nb_entries) {
		ret = -EINVAL;
		goto unlock;
	}

	/* update the tail value */
	header->tail = new_tail;
	ret = count;

unlock:
	mutex_unlock(&s1->fault_queue_lock);
	return ret;
}

static const struct file_operations hwpt_fault_fops = {
	.owner		= THIS_MODULE,
	.read		= hwpt_fault_fops_read,
	.write		= hwpt_fault_fops_write,
};

static int iommufd_hw_pagetable_get_fault_fd(struct iommufd_hw_pagetable_s1 *s1)
{
	struct file *filep;
	int fdno, ret;

	fdno = ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		return ret;

	filep = anon_inode_getfile("[hwpt-fault]", &hwpt_fault_fops,
				   s1, O_RDWR);
	if (IS_ERR(filep)) {
		put_unused_fd(fdno);
		return PTR_ERR(filep);
	}

	filep->f_mode |= (FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	fd_install(fdno, filep);

	s1->fault_file = filep;
	s1->fault_fd = fdno;

	return 0;
}

static enum iommu_page_response_code
iommufd_hw_pagetable_iopf_handler(struct iommu_fault *fault,
				  struct device *dev, void *data)
{
	struct iommufd_hw_pagetable_s1 *s1 =
				(struct iommufd_hw_pagetable_s1 *)data;
	struct iommufd_hw_pagetable *hwpt =
		container_of(s1, struct iommufd_hw_pagetable, s1_hwpt);
	struct iommufd_stage1_dma_fault *header =
		(struct iommufd_stage1_dma_fault *)s1->fault_pages;
	struct iommu_fault *new;
	int head, tail, size;
	u32 dev_id;
	ioasid_t pasid = (fault->prm.flags & IOMMU_FAULT_PAGE_REQUEST_PASID_VALID) ?
			 fault->prm.pasid : INVALID_IOASID;
	enum iommu_page_response_code resp = IOMMU_PAGE_RESP_ASYNC;

	if (WARN_ON(!header))
		return IOMMU_PAGE_RESP_FAILURE;

	dev_id = iommufd_hw_pagetable_get_dev_id(hwpt, dev, pasid);
	if (dev_id == IOMMUFD_INVALID_ID)
		return IOMMU_PAGE_RESP_FAILURE;

	fault->dev_id = dev_id;
	mutex_lock(&s1->fault_queue_lock);

	new = (struct iommu_fault *)(s1->fault_pages + header->offset +
				     header->head * header->entry_size);

	pr_debug("%s, enque fault event\n", __func__);
	head = header->head;
	tail = header->tail;
	size = header->nb_entries;

	if (CIRC_SPACE(head, tail, size) < 1) {
		resp = IOMMU_PAGE_RESP_FAILURE;
		goto unlock;
	}

	*new = *fault;
	header->head = (head + 1) % size;
unlock:
	mutex_unlock(&s1->fault_queue_lock);
	if (resp != IOMMU_PAGE_RESP_ASYNC)
		return resp;

	mutex_lock(&s1->notify_gate);
	pr_debug("%s, signal userspace!\n", __func__);
	if (s1->trigger)
		eventfd_signal(s1->trigger, 1);
	mutex_unlock(&s1->notify_gate);

	return resp;
}

#define DMA_FAULT_RING_LENGTH 512

static int
iommufd_hw_pagetable_dma_fault_init(struct iommufd_hw_pagetable_s1 *s1,
				    int eventfd)
{
	struct iommufd_stage1_dma_fault *header;
	size_t size;
	int rc;

	mutex_init(&s1->fault_queue_lock);
	mutex_init(&s1->notify_gate);

	/*
	 * We provision 1 page for the header and space for
	 * DMA_FAULT_RING_LENGTH fault records in the ring buffer.
	 */
	size = ALIGN(sizeof(struct iommu_fault) *
		     DMA_FAULT_RING_LENGTH, PAGE_SIZE) + PAGE_SIZE;

	s1->fault_pages = kzalloc(size, GFP_KERNEL);
	if (!s1->fault_pages)
		return -ENOMEM;

	header = (struct iommufd_stage1_dma_fault *)s1->fault_pages;
	header->entry_size = sizeof(struct iommu_fault);
	header->nb_entries = DMA_FAULT_RING_LENGTH;
	header->offset = PAGE_SIZE;
	s1->fault_region_size = size;

	rc = iommufd_hw_pagetable_eventfd_setup(&s1->trigger, eventfd);
	if (rc)
		goto out_free;

	rc = iommufd_hw_pagetable_get_fault_fd(s1);
	if (rc)
		goto out_destroy_eventfd;

	return rc;

out_destroy_eventfd:
	iommufd_hw_pagetable_eventfd_destroy(&s1->trigger);
out_free:
	kfree(s1->fault_pages);
	return rc;
}

static void
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable_s1 *s1)
{
	struct iommufd_stage1_dma_fault *header =
		(struct iommufd_stage1_dma_fault *)s1->fault_pages;

	WARN_ON(header->tail != header->head);
	iommufd_hw_pagetable_eventfd_destroy(&s1->trigger);
	kfree(s1->fault_pages);
	mutex_destroy(&s1->fault_queue_lock);
	mutex_destroy(&s1->notify_gate);
}

int iommufd_alloc_s1_hwpt(struct iommufd_ucmd *ucmd)
{
	struct iommu_alloc_s1_hwpt *cmd = ucmd->cmd;
	struct iommufd_object *stage2_obj;
	struct iommufd_object *dev_obj;
	struct iommufd_device *idev;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_hw_pagetable *stage2;
	struct iommufd_hw_pagetable_s1 *s1;
	union iommu_stage1_config s1_config;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	if (cmd->eventfd < 0)
		return -EINVAL;

	rc = copy_struct_from_user(&s1_config, sizeof(s1_config),
				   (void __user *)cmd->stage1_config_uptr,
				   cmd->stage1_config_len);
	if (rc)
		return rc;

	stage2_obj = iommufd_get_object(ucmd->ictx, cmd->stage2_hwpt_id,
					IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(stage2_obj))
		return PTR_ERR(stage2_obj);

	stage2 = container_of(stage2_obj, struct iommufd_hw_pagetable, obj);

	dev_obj = iommufd_get_object(ucmd->ictx, cmd->dev_id,
				     IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(dev_obj)) {
		rc = PTR_ERR(dev_obj);
		goto out_put_stage2;
	}

	idev = container_of(dev_obj, struct iommufd_device, obj);

	hwpt = iommufd_object_alloc(ucmd->ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE_S1);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_put_dev;
	}

	xa_init_flags(&hwpt->devices, XA_FLAGS_ALLOC1 | XA_FLAGS_ACCOUNT);
	mutex_init(&hwpt->devices_lock);

	hwpt->domain = iommu_alloc_nested_domain(idev->dev->bus,
						 stage2->domain,
						 cmd->stage1_ptr,
						 &s1_config);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	s1 = &hwpt->s1_hwpt;
	s1->stage2 = stage2;

	rc = iommufd_hw_pagetable_dma_fault_init(s1, cmd->eventfd);
	if (rc)
		goto out_free_domain;

	cmd->out_hwpt_id = hwpt->obj.id;
	cmd->out_fault_fd = s1->fault_fd;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_destroy_dma;

	hwpt->domain->iopf_handler = iommufd_hw_pagetable_iopf_handler;
	hwpt->domain->fault_data = s1;

//	mutex_lock(&stage2->kernel.mutex);
//	list_add_tail(&s1->stage1_domains_item, &stage2->kernel.stage1_domains);
//	mutex_unlock(&stage2->kernel.mutex);
	iommufd_object_finalize(ucmd->ictx, &hwpt->obj);
	/* No need to hold refcount on dev_obj per hwpt allocation */
	iommufd_put_object(dev_obj);
	/* Caller is a user of stage2 until destroy */
	iommufd_put_object_keep_user(stage2_obj);

	return 0;
out_destroy_dma:
	iommufd_hw_pagetable_dma_fault_destroy(s1);
out_free_domain:
	iommu_domain_free(hwpt->domain);
out_abort:
	iommufd_object_abort(ucmd->ictx, &hwpt->obj);
out_put_dev:
	iommufd_put_object(dev_obj);
out_put_stage2:
	iommufd_put_object(stage2_obj);
	return rc;
}

int iommufd_hwpt_invalidate_cache(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_invalidate_s1_cache *cmd = ucmd->cmd;
	struct iommufd_object *obj;
	struct iommufd_hw_pagetable *hwpt;
	int rc = 0;

	if (cmd->flags)
		return -EOPNOTSUPP;

	/* TODO: more sanity check when the struct is finalized */
	obj = iommufd_get_object(ucmd->ictx, cmd->hwpt_id,
				 IOMMUFD_OBJ_HW_PAGETABLE_S1);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	hwpt = container_of(obj, struct iommufd_hw_pagetable, obj);

	iommu_domain_cache_inv(hwpt->domain, &cmd->info);

	iommufd_put_object(obj);
	return rc;
}

int iommufd_hwpt_page_response(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_page_response *cmd = ucmd->cmd;
	struct iommufd_object *obj, *dev_obj;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_device *idev;
	int rc = 0;

	if (cmd->flags)
		return -EOPNOTSUPP;

	/* TODO: more sanity check when the struct is finalized */
	obj = iommufd_get_object(ucmd->ictx, cmd->hwpt_id,
				 IOMMUFD_OBJ_HW_PAGETABLE_S1);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	hwpt = container_of(obj, struct iommufd_hw_pagetable, obj);

	dev_obj = iommufd_get_object(ucmd->ictx,
				     cmd->dev_id, IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(dev_obj)) {
		rc = PTR_ERR(obj);
		goto out_put_hwpt;
	}

	idev = container_of(dev_obj, struct iommufd_device, obj);
	rc = iommu_page_response(idev->dev, &cmd->resp);
	iommufd_put_object(dev_obj);
out_put_hwpt:
	iommufd_put_object(obj);
	return rc;
}
