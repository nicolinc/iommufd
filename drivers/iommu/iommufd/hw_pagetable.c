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
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable_s1 *s1_hwpt);

void iommufd_hw_pagetable_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);

	WARN_ON(!xa_empty(&hwpt->devices));

	if (hwpt->type == IOMMUFD_HWPT_IOAS_AUTO ||
	    hwpt->type == IOMMUFD_HWPT_IOAS_USER) {
		struct iommufd_hw_pagetable_ioas *ioas_hwpt = &hwpt->ioas_hwpt;

		refcount_dec(&ioas_hwpt->ioas->obj.users);
		if (hwpt->type == IOMMUFD_HWPT_IOAS_USER)
			iopt_table_remove_domain(&ioas_hwpt->ioas->iopt,
						 hwpt->domain);
	} else if (hwpt->type == IOMMUFD_HWPT_USER_S1) {
		struct iommufd_hw_pagetable_s1 *s1_hwpt = &hwpt->s1_hwpt;

		if (s1_hwpt->stage2)
			refcount_dec(&s1_hwpt->stage2->obj.users);
		iommufd_hw_pagetable_dma_fault_destroy(s1_hwpt);
	}

	if (hwpt->user_data)
		kfree(hwpt->user_data);
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
	struct iommufd_hw_pagetable_ioas *ioas_hwpt;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	hwpt->type = IOMMUFD_HWPT_IOAS_AUTO;
	hwpt->domain = iommu_domain_alloc(dev->bus);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	xa_init_flags(&hwpt->devices, XA_FLAGS_ALLOC1 | XA_FLAGS_ACCOUNT);
	mutex_init(&hwpt->devices_lock);
	ioas_hwpt = &hwpt->ioas_hwpt;
	INIT_LIST_HEAD(&ioas_hwpt->auto_domains_item);
	ioas_hwpt->ioas = ioas;
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
	struct iommufd_hw_pagetable_s1 *s1_hwpt = filep->private_data;
	loff_t pos = *ppos;
	void *base = s1_hwpt->fault_pages;
	size_t size = s1_hwpt->fault_region_size;
	int ret = -EFAULT;

	if (pos >= size)
		return -EINVAL;

	count = min(count, (size_t)(size - pos));

	mutex_lock(&s1_hwpt->fault_queue_lock);
	if (!copy_to_user(buf, base + pos, count)) {
		*ppos += count;
		ret = count;
	}
	mutex_unlock(&s1_hwpt->fault_queue_lock);

	return ret;
}

static ssize_t hwpt_fault_fops_write(struct file *filep,
				     const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct iommufd_hw_pagetable_s1 *s1_hwpt = filep->private_data;
	loff_t pos = *ppos;
	void *base = s1_hwpt->fault_pages;
	struct iommufd_stage1_dma_fault *header =
			(struct iommufd_stage1_dma_fault *)base;
	size_t size = s1_hwpt->fault_region_size;
	u32 new_tail;
	int ret = -EFAULT;

	if (pos >= size)
		return -EINVAL;

	count = min(count, (size_t)(size - pos));

	mutex_lock(&s1_hwpt->fault_queue_lock);

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
	mutex_unlock(&s1_hwpt->fault_queue_lock);
	return ret;
}

static const struct file_operations hwpt_fault_fops = {
	.owner		= THIS_MODULE,
	.read		= hwpt_fault_fops_read,
	.write		= hwpt_fault_fops_write,
};

static int iommufd_hw_pagetable_get_fault_fd(struct iommufd_hw_pagetable_s1 *s1_hwpt)
{
	struct file *filep;
	int fdno, ret;

	fdno = ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		return ret;

	filep = anon_inode_getfile("[hwpt-fault]", &hwpt_fault_fops,
				   s1_hwpt, O_RDWR);
	if (IS_ERR(filep)) {
		put_unused_fd(fdno);
		return PTR_ERR(filep);
	}

	filep->f_mode |= (FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	fd_install(fdno, filep);

	s1_hwpt->fault_file = filep;
	s1_hwpt->fault_fd = fdno;

	return 0;
}

static int iommufd_hw_pagetable_fault_handler(struct device *dev,
					      struct iommu_fault *fault,
					      void *cookie)
{
	struct iommufd_hw_pagetable_s1 *s1_hwpt =
				(struct iommufd_hw_pagetable_s1 *)cookie;
	struct iommufd_hw_pagetable *hwpt =
		container_of(s1_hwpt, struct iommufd_hw_pagetable, s1_hwpt);
	struct iommufd_stage1_dma_fault *header =
		(struct iommufd_stage1_dma_fault *)s1_hwpt->fault_pages;
	struct iommu_fault *new;
	int head, tail, size, rc = 0;
	ioasid_t pasid;
	u32 dev_id;

	if (WARN_ON(!header))
		return -ENOENT;

	if (fault->type == IOMMU_FAULT_PAGE_REQ &&
	    fault->prm.flags & IOMMU_FAULT_PAGE_REQUEST_PASID_VALID)
                pasid = fault->prm.pasid;
	else if (fault->type == IOMMU_FAULT_DMA_UNRECOV &&
		 fault->event.flags & IOMMU_FAULT_UNRECOV_PASID_VALID)
		pasid = fault->event.pasid;
	else
		pasid = INVALID_IOASID;

	dev_id = iommufd_hw_pagetable_get_dev_id(hwpt, dev, pasid);
	if (dev_id == IOMMUFD_INVALID_ID)
		return -ENODEV;

	fault->dev_id = dev_id;
	mutex_lock(&s1_hwpt->fault_queue_lock);

	new = (struct iommu_fault *)(s1_hwpt->fault_pages + header->offset +
				     header->head * header->entry_size);

	pr_debug("%s, enque fault event\n", __func__);
	head = header->head;
	tail = header->tail;
	size = header->nb_entries;

	if (CIRC_SPACE(head, tail, size) < 1) {
		rc = -EINVAL;
		goto unlock;
	}

	*new = *fault;
	header->head = (head + 1) % size;
unlock:
	mutex_unlock(&s1_hwpt->fault_queue_lock);
	if (rc)
		return rc;

	mutex_lock(&s1_hwpt->notify_gate);
	pr_debug("%s, signal userspace!\n", __func__);
	if (s1_hwpt->trigger)
		eventfd_signal(s1_hwpt->trigger, 1);
	mutex_unlock(&s1_hwpt->notify_gate);

	return rc;
}

#define DMA_FAULT_RING_LENGTH 512

static int
iommufd_hw_pagetable_dma_fault_init(struct iommufd_hw_pagetable_s1 *s1_hwpt,
				    struct device *fault_dev, int eventfd)
{
	struct iommufd_stage1_dma_fault *header;
	size_t size;
	int rc;

	mutex_init(&s1_hwpt->fault_queue_lock);
	mutex_init(&s1_hwpt->notify_gate);

	/*
	 * We provision 1 page for the header and space for
	 * DMA_FAULT_RING_LENGTH fault records in the ring buffer.
	 */
	size = ALIGN(sizeof(struct iommu_fault) *
		     DMA_FAULT_RING_LENGTH, PAGE_SIZE) + PAGE_SIZE;

	s1_hwpt->fault_pages = kzalloc(size, GFP_KERNEL);
	if (!s1_hwpt->fault_pages)
		return -ENOMEM;

	header = (struct iommufd_stage1_dma_fault *)s1_hwpt->fault_pages;
	header->entry_size = sizeof(struct iommu_fault);
	header->nb_entries = DMA_FAULT_RING_LENGTH;
	header->offset = PAGE_SIZE;
	s1_hwpt->fault_region_size = size;

	rc = iommufd_hw_pagetable_eventfd_setup(&s1_hwpt->trigger, eventfd);
	if (rc)
		goto out_free;

	rc = iommufd_hw_pagetable_get_fault_fd(s1_hwpt);
	if (rc)
		goto out_destroy_eventfd;

	rc = iommu_register_device_fault_handler(fault_dev,
			iommufd_hw_pagetable_fault_handler, s1_hwpt);
	if (rc)
		goto out_destroy_eventfd;

	s1_hwpt->fault_dev = fault_dev;

	return rc;

out_destroy_eventfd:
	iommufd_hw_pagetable_eventfd_destroy(&s1_hwpt->trigger);
out_free:
	kfree(s1_hwpt->fault_pages);
	return rc;
}

static void
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable_s1 *s1_hwpt)
{
	struct iommufd_stage1_dma_fault *header =
		(struct iommufd_stage1_dma_fault *)s1_hwpt->fault_pages;

	WARN_ON(header->tail != header->head);
	if (s1_hwpt->fault_dev)
		iommu_unregister_device_fault_handler(s1_hwpt->fault_dev);
	iommufd_hw_pagetable_eventfd_destroy(&s1_hwpt->trigger);
	kfree(s1_hwpt->fault_pages);
	mutex_destroy(&s1_hwpt->fault_queue_lock);
	mutex_destroy(&s1_hwpt->notify_gate);
}

static struct iommufd_hw_pagetable *
iommufd_alloc_s1_hwpt(struct iommufd_ctx *ictx,
		      struct iommufd_device *idev,
		      struct iommu_alloc_hwpt *cmd,
		      void *user_data)
{
	struct iommu_domain *parent_domain = NULL;
	struct iommufd_hw_pagetable_s1 *s1_hwpt;
	struct iommufd_hw_pagetable *stage2;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_object *obj;
	int rc;

	if (cmd->flags & IOMMU_HWPT_FLAG_NESTING) {
		obj = iommufd_get_object(ictx, cmd->parent_id,
					 IOMMUFD_OBJ_HW_PAGETABLE);
		if (IS_ERR(obj))
			return ERR_PTR(-EINVAL);

		stage2 = container_of(obj, struct iommufd_hw_pagetable, obj);
		parent_domain = stage2->domain;
	}

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_put_obj;
	}

	hwpt->type = IOMMUFD_HWPT_USER_S1;
	hwpt->domain = iommu_domain_alloc_user(idev->dev, parent_domain,
					       user_data, IOMMU_DOMAIN_NESTING);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	xa_init_flags(&hwpt->devices, XA_FLAGS_ALLOC1 | XA_FLAGS_ACCOUNT);
	mutex_init(&hwpt->devices_lock);

	s1_hwpt = &hwpt->s1_hwpt;

	/* Caller is a user of stage2 until destroy */
	if (cmd->flags & IOMMU_HWPT_FLAG_NESTING) {
		s1_hwpt->stage2 = stage2;
		iommufd_put_object_keep_user(obj);
	}

	return hwpt;
out_abort:
	iommufd_object_abort(ictx, &hwpt->obj);
out_put_obj:
	if (cmd->flags & IOMMU_HWPT_FLAG_NESTING)
		iommufd_put_object(obj);
	return ERR_PTR(rc);
}

static struct iommufd_hw_pagetable *
iommufd_alloc_s2_hwpt(struct iommufd_ctx *ictx,
		      struct iommufd_device *idev,
		      struct iommu_alloc_hwpt *cmd)
{
	struct iommufd_object *obj;
	struct iommufd_ioas *ioas;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_hw_pagetable_ioas *ioas_hwpt;
	int rc;

	obj = iommufd_get_object(ictx, cmd->parent_id, IOMMUFD_OBJ_IOAS);
	if (IS_ERR(obj))
		return ERR_PTR(-EINVAL);

	ioas = container_of(obj, struct iommufd_ioas, obj);

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_put_ioas;
	}

	hwpt->type = IOMMUFD_HWPT_IOAS_USER;
	hwpt->domain = iommu_domain_alloc(idev->dev->bus);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	rc = iopt_table_add_domain(&ioas->iopt, hwpt->domain);
	if (rc)
		goto out_free_domain;

	xa_init_flags(&hwpt->devices, XA_FLAGS_ALLOC1 | XA_FLAGS_ACCOUNT);
	mutex_init(&hwpt->devices_lock);

	ioas_hwpt = &hwpt->ioas_hwpt;
	INIT_LIST_HEAD(&ioas_hwpt->auto_domains_item);
	ioas_hwpt->ioas = ioas;
	/* The calling driver is a user until the hw_pagetable is destroyed */
	iommufd_put_object_keep_user(obj);
	return hwpt;
out_free_domain:
	iommu_domain_free(hwpt->domain);
out_abort:
	iommufd_object_abort(ictx, &hwpt->obj);
out_put_ioas:
	iommufd_put_object(obj);
	return ERR_PTR(rc);
}

static const size_t iommufd_hwpt_data_len[] = {
	[IOMMU_HWPT_DATA_NONE] = 0,
	[IOMMU_HWPT_DATA_INTEL_VTD] = sizeof(struct iommu_hwpt_intel_vtd),
};

int iommufd_alloc_hwpt(struct iommufd_ucmd *ucmd)
{
	struct iommu_alloc_hwpt *cmd = ucmd->cmd;
	struct iommufd_object *dev_obj;
	struct iommufd_device *idev;
	struct iommufd_hw_pagetable *hwpt;
	void *user_data = NULL;
	int rc;

	if (cmd->reserved || cmd->hwpt_type > IOMMU_HWPT_TYPE_S1)
		return -EOPNOTSUPP;

	dev_obj = iommufd_get_object(ucmd->ictx, cmd->dev_id,
				     IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(dev_obj))
		return PTR_ERR(dev_obj);

	idev = container_of(dev_obj, struct iommufd_device, obj);

	if (cmd->data_len && cmd->data_type != IOMMU_HWPT_DATA_NONE) {
		if (iommufd_hwpt_data_len[cmd->data_type] != cmd->data_len) {
			rc = -EINVAL;
			goto out_put_dev;
		}

		user_data = kzalloc(cmd->data_len, GFP_KERNEL);
		if (!user_data) {
			rc = -ENOMEM;
			goto out_put_dev;
		}

		rc = copy_struct_from_user(user_data, cmd->data_len,
					   (void __user *)cmd->data_uptr,
					   cmd->data_len);
		if (rc)
			goto out_put_dev;
	}

	switch (cmd->hwpt_type) {
	case IOMMU_HWPT_TYPE_S2:
		hwpt = iommufd_alloc_s2_hwpt(ucmd->ictx, idev, cmd);
		break;
	case IOMMU_HWPT_TYPE_S1:
		hwpt = iommufd_alloc_s1_hwpt(ucmd->ictx, idev, cmd, user_data);
		break;
	default:
		rc = -EINVAL;
		goto out_free_data;
	}

	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_free_data;
	}

	hwpt->user_data = user_data;
	cmd->out_hwpt_id = hwpt->obj.id;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_destroy_hwpt;

	iommufd_object_finalize(ucmd->ictx, &hwpt->obj);
	/* No need to hold refcount on dev_obj per hwpt allocation */
	iommufd_put_object(dev_obj);
	return 0;
out_destroy_hwpt:
	iommufd_object_abort_and_destroy(ucmd->ictx, &hwpt->obj);
out_free_data:
	if (user_data)
		kfree(user_data);
out_put_dev:
	iommufd_put_object(dev_obj);
	return rc;
}

static int iommufd_add_hwpt_event_fault(struct iommufd_hw_pagetable *hwpt,
					struct iommufd_device *idev,
					s32 eventfd, s32 *out_fd)
{
	int rc;

	if (hwpt->type != IOMMUFD_HWPT_USER_S1)
		return -EINVAL;

	rc = iommufd_hw_pagetable_dma_fault_init(&hwpt->s1_hwpt, idev->dev,
						 eventfd);
	if (rc)
		return rc;

	*out_fd = hwpt->s1_hwpt.fault_fd;

	return 0;
}

int iommufd_add_hwpt_event(struct iommufd_ucmd *ucmd)
{
	struct iommu_add_hwpt_event *cmd = ucmd->cmd;
	struct iommufd_object *dev_obj, *hwpt_obj;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_device *idev;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	if (cmd->eventfd < 0)
		return -EINVAL;

	dev_obj = iommufd_get_object(ucmd->ictx, cmd->dev_id,
				     IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(dev_obj))
		return PTR_ERR(dev_obj);

	idev = container_of(dev_obj, struct iommufd_device, obj);

	hwpt_obj = iommufd_get_object(ucmd->ictx, cmd->hwpt_id,
				      IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt_obj)) {
		rc = PTR_ERR(hwpt_obj);
		goto out_put_dev;
	}

	hwpt = container_of(hwpt_obj, struct iommufd_hw_pagetable, obj);

	switch (cmd->type) {
	case IOMMU_HWPT_EVENT_FAULT:
		rc = iommufd_add_hwpt_event_fault(hwpt, idev, cmd->eventfd,
						  &cmd->out_fd);
		break;
	default:
		rc = -EOPNOTSUPP;
	}
	if (rc)
		goto out_put_hwpt;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_destroy_dma_fault;

	iommufd_put_object(hwpt_obj);
	iommufd_put_object(dev_obj);
	return 0;
out_destroy_dma_fault:
	iommufd_hw_pagetable_dma_fault_destroy(&hwpt->s1_hwpt);
out_put_hwpt:
	iommufd_put_object(hwpt_obj);
out_put_dev:
	iommufd_put_object(dev_obj);
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
				 IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	hwpt = container_of(obj, struct iommufd_hw_pagetable, obj);

	if (hwpt->type != IOMMUFD_HWPT_USER_S1) {
		rc = -EINVAL;
		goto out_put_hwpt;
	}

	iommu_domain_cache_inv(hwpt->domain, &cmd->info);
out_put_hwpt:
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
				 IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	hwpt = container_of(obj, struct iommufd_hw_pagetable, obj);

	if (hwpt->type != IOMMUFD_HWPT_USER_S1) {
		rc = -EINVAL;
		goto out_put_hwpt;
	}

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
