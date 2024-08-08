// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation
 */
#define pr_fmt(fmt) "iommufd: " fmt

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/iommufd.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <uapi/linux/iommufd.h>

#include "../iommu-priv.h"
#include "iommufd_private.h"

/* IOMMUFD_OBJ_EVENTQ_IOPF Functions */

static int iommufd_eventq_iopf_enable(struct iommufd_device *idev)
{
	struct device *dev = idev->dev;
	int ret;

	/*
	 * Once we turn on PCI/PRI support for VF, the response failure code
	 * should not be forwarded to the hardware due to PRI being a shared
	 * resource between PF and VFs. There is no coordination for this
	 * shared capability. This waits for a vPRI reset to recover.
	 */
	if (dev_is_pci(dev) && to_pci_dev(dev)->is_virtfn)
		return -EINVAL;

	mutex_lock(&idev->iopf_lock);
	/* Device iopf has already been on. */
	if (++idev->iopf_enabled > 1) {
		mutex_unlock(&idev->iopf_lock);
		return 0;
	}

	ret = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_IOPF);
	if (ret)
		--idev->iopf_enabled;
	mutex_unlock(&idev->iopf_lock);

	return ret;
}

static void iommufd_eventq_iopf_disable(struct iommufd_device *idev)
{
	mutex_lock(&idev->iopf_lock);
	if (!WARN_ON(idev->iopf_enabled == 0)) {
		if (--idev->iopf_enabled == 0)
			iommu_dev_disable_feature(idev->dev, IOMMU_DEV_FEAT_IOPF);
	}
	mutex_unlock(&idev->iopf_lock);
}

static int __eventq_iopf_domain_attach_dev(struct iommufd_hw_pagetable *hwpt,
					   struct iommufd_device *idev)
{
	struct iommufd_attach_handle *handle;
	int ret;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->idev = idev;
	ret = iommu_attach_group_handle(hwpt->domain, idev->igroup->group,
					&handle->handle);
	if (ret)
		kfree(handle);

	return ret;
}

int iommufd_eventq_iopf_domain_attach_dev(struct iommufd_hw_pagetable *hwpt,
					  struct iommufd_device *idev)
{
	int ret;

	if (!hwpt->fault)
		return -EINVAL;

	ret = iommufd_eventq_iopf_enable(idev);
	if (ret)
		return ret;

	ret = __eventq_iopf_domain_attach_dev(hwpt, idev);
	if (ret)
		iommufd_eventq_iopf_disable(idev);

	return ret;
}

static void
iommufd_eventq_iopf_auto_response(struct iommufd_hw_pagetable *hwpt,
				  struct iommufd_attach_handle *handle)
{
	struct iommufd_eventq_iopf *fault = hwpt->fault;
	struct iopf_group *group, *next;
	unsigned long index;

	if (!fault)
		return;

	mutex_lock(&fault->common.mutex);
	list_for_each_entry_safe(group, next, &fault->common.deliver, node) {
		if (group->attach_handle != &handle->handle)
			continue;
		list_del(&group->node);
		iopf_group_response(group, IOMMU_PAGE_RESP_INVALID);
		iopf_free_group(group);
	}

	xa_for_each(&fault->response, index, group) {
		if (group->attach_handle != &handle->handle)
			continue;
		xa_erase(&fault->response, index);
		iopf_group_response(group, IOMMU_PAGE_RESP_INVALID);
		iopf_free_group(group);
	}
	mutex_unlock(&fault->common.mutex);
}

static struct iommufd_attach_handle *
iommufd_device_get_attach_handle(struct iommufd_device *idev)
{
	struct iommu_attach_handle *handle;

	handle = iommu_attach_handle_get(idev->igroup->group, IOMMU_NO_PASID, 0);
	if (IS_ERR(handle))
		return NULL;

	return to_iommufd_handle(handle);
}

void iommufd_eventq_iopf_domain_detach_dev(struct iommufd_hw_pagetable *hwpt,
					   struct iommufd_device *idev)
{
	struct iommufd_attach_handle *handle;

	handle = iommufd_device_get_attach_handle(idev);
	iommu_detach_group_handle(hwpt->domain, idev->igroup->group);
	iommufd_eventq_iopf_auto_response(hwpt, handle);
	iommufd_eventq_iopf_disable(idev);
	kfree(handle);
}

static int __eventq_iopf_domain_replace_dev(struct iommufd_device *idev,
					    struct iommufd_hw_pagetable *hwpt,
					    struct iommufd_hw_pagetable *old)
{
	struct iommufd_attach_handle *handle, *curr = NULL;
	int ret;

	if (old->fault)
		curr = iommufd_device_get_attach_handle(idev);

	if (hwpt->fault) {
		handle = kzalloc(sizeof(*handle), GFP_KERNEL);
		if (!handle)
			return -ENOMEM;

		handle->idev = idev;
		ret = iommu_replace_group_handle(idev->igroup->group,
						 hwpt->domain, &handle->handle);
	} else {
		ret = iommu_replace_group_handle(idev->igroup->group,
						 hwpt->domain, NULL);
	}

	if (!ret && curr) {
		iommufd_eventq_iopf_auto_response(old, curr);
		kfree(curr);
	}

	return ret;
}

int iommufd_eventq_iopf_domain_replace_dev(struct iommufd_device *idev,
					   struct iommufd_hw_pagetable *hwpt,
					   struct iommufd_hw_pagetable *old)
{
	bool iopf_off = !hwpt->fault && old->fault;
	bool iopf_on = hwpt->fault && !old->fault;
	int ret;

	if (iopf_on) {
		ret = iommufd_eventq_iopf_enable(idev);
		if (ret)
			return ret;
	}

	ret = __eventq_iopf_domain_replace_dev(idev, hwpt, old);
	if (ret) {
		if (iopf_on)
			iommufd_eventq_iopf_disable(idev);
		return ret;
	}

	if (iopf_off)
		iommufd_eventq_iopf_disable(idev);

	return 0;
}

void iommufd_eventq_iopf_destroy(struct iommufd_object *obj)
{
	struct iommufd_eventq *eventq =
		container_of(obj, struct iommufd_eventq, obj);
	struct iopf_group *group, *next;

	/*
	 * The iommufd object's reference count is zero at this point.
	 * We can be confident that no other threads are currently
	 * accessing this pointer. Therefore, acquiring the mutex here
	 * is unnecessary.
	 */
	list_for_each_entry_safe(group, next, &eventq->deliver, node) {
		list_del(&group->node);
		iopf_group_response(group, IOMMU_PAGE_RESP_INVALID);
		iopf_free_group(group);
	}
	xa_destroy(&to_eventq_iopf(eventq)->response);
	mutex_destroy(&eventq->mutex);
}

static void iommufd_compose_iopf_message(struct iommu_fault *fault,
					 struct iommu_hwpt_pgfault *hwpt_fault,
					 struct iommufd_device *idev,
					 u32 cookie)
{
	hwpt_fault->flags = fault->prm.flags;
	hwpt_fault->dev_id = idev->obj.id;
	hwpt_fault->pasid = fault->prm.pasid;
	hwpt_fault->grpid = fault->prm.grpid;
	hwpt_fault->perm = fault->prm.perm;
	hwpt_fault->addr = fault->prm.addr;
	hwpt_fault->length = 0;
	hwpt_fault->cookie = cookie;
}

static ssize_t iommufd_eventq_iopf_fops_read(struct iommufd_eventq *eventq,
					     char __user *buf, size_t count,
					     loff_t *ppos)
{
	struct iommufd_eventq_iopf *fault = to_eventq_iopf(eventq);
	size_t fault_size = sizeof(struct iommu_hwpt_pgfault);
	struct iommu_hwpt_pgfault data;
	struct iommufd_device *idev;
	struct iopf_group *group;
	struct iopf_fault *iopf;
	size_t done = 0;
	int rc = 0;

	if (*ppos || count % fault_size)
		return -ESPIPE;

	mutex_lock(&eventq->mutex);
	while (!list_empty(&eventq->deliver) && count > done) {
		group = list_first_entry(&eventq->deliver, struct iopf_group,
					 node);

		if (group->fault_count * fault_size > count - done)
			break;

		rc = xa_alloc(&fault->response, &group->cookie, group,
			      xa_limit_32b, GFP_KERNEL);
		if (rc)
			break;

		idev = to_iommufd_handle(group->attach_handle)->idev;
		list_for_each_entry(iopf, &group->faults, list) {
			iommufd_compose_iopf_message(&iopf->fault, &data, idev,
						     group->cookie);
			if (copy_to_user(buf + done, &data, fault_size)) {
				xa_erase(&fault->response, group->cookie);
				rc = -EFAULT;
				break;
			}
			done += fault_size;
		}

		list_del(&group->node);
	}
	mutex_unlock(&eventq->mutex);

	return done == 0 ? rc : done;
}

static ssize_t iommufd_eventq_iopf_fops_write(struct iommufd_eventq *eventq,
					      const char __user *buf,
					      size_t count, loff_t *ppos)
{
	size_t response_size = sizeof(struct iommu_hwpt_page_response);
	struct iommufd_eventq_iopf *fault = to_eventq_iopf(eventq);
	struct iommu_hwpt_page_response response;
	struct iopf_group *group;
	size_t done = 0;
	int rc = 0;

	if (*ppos || count % response_size)
		return -ESPIPE;

	mutex_lock(&eventq->mutex);
	while (count > done) {
		rc = copy_from_user(&response, buf + done, response_size);
		if (rc)
			break;

		static_assert((int)IOMMUFD_PAGE_RESP_SUCCESS ==
			      (int)IOMMU_PAGE_RESP_SUCCESS);
		static_assert((int)IOMMUFD_PAGE_RESP_INVALID ==
			      (int)IOMMU_PAGE_RESP_INVALID);
		if (response.code != IOMMUFD_PAGE_RESP_SUCCESS &&
		    response.code != IOMMUFD_PAGE_RESP_INVALID) {
			rc = -EINVAL;
			break;
		}

		group = xa_erase(&fault->response, response.cookie);
		if (!group) {
			rc = -EINVAL;
			break;
		}

		iopf_group_response(group, response.code);
		iopf_free_group(group);
		done += response_size;
	}
	mutex_unlock(&eventq->mutex);

	return done == 0 ? rc : done;
}

static const struct iommufd_eventq_ops iommufd_eventq_iopf_ops = {
	.read = &iommufd_eventq_iopf_fops_read,
	.write = &iommufd_eventq_iopf_fops_write,
};

/* IOMMUFD_OBJ_EVENTQ_VIRQ Functions */

void iommufd_eventq_virq_abort(struct iommufd_object *obj)
{
	struct iommufd_eventq *eventq =
		container_of(obj, struct iommufd_eventq, obj);
	struct iommufd_eventq_virq *eventq_virq = to_eventq_virq(eventq);
	struct iommufd_viommu *viommu = eventq_virq->viommu;
	struct iommufd_virq *virq, *next;

	lockdep_assert_held_write(&viommu->virqs_rwsem);

	list_for_each_entry_safe(virq, next, &eventq->deliver, node) {
		list_del(&virq->node);
		kfree(virq);
	}

	if (eventq_virq->irq_wq)
		destroy_workqueue(eventq_virq->irq_wq);
	refcount_dec(&viommu->obj.users);
	mutex_destroy(&eventq->mutex);
	list_del(&eventq_virq->node);
}

void iommufd_eventq_virq_destroy(struct iommufd_object *obj)
{
	struct iommufd_eventq_virq *eventq_virq =
		to_eventq_virq(container_of(obj, struct iommufd_eventq, obj));

	down_write(&eventq_virq->viommu->virqs_rwsem);
	iommufd_eventq_virq_abort(obj);
	up_write(&eventq_virq->viommu->virqs_rwsem);
}

static ssize_t iommufd_eventq_virq_fops_read(struct iommufd_eventq *eventq,
					     char __user *buf, size_t count,
					     loff_t *ppos)
{
	size_t done = 0;
	int rc = 0;

	if (*ppos)
		return -ESPIPE;

	mutex_lock(&eventq->mutex);
	while (!list_empty(&eventq->deliver) && count > done) {
		struct iommufd_virq *virq = list_first_entry(
			&eventq->deliver, struct iommufd_virq, node);
		void *virq_data = (void *)virq + sizeof(*virq);

		if (virq->irq_len > count - done)
			break;

		if (copy_to_user(buf + done, virq_data, virq->irq_len)) {
			rc = -EFAULT;
			break;
		}
		done += virq->irq_len;
		list_del(&virq->node);
		kfree(virq);
	}
	mutex_unlock(&eventq->mutex);

	return done == 0 ? rc : done;
}

static const struct iommufd_eventq_ops iommufd_eventq_virq_ops = {
	.read = &iommufd_eventq_virq_fops_read,
};

/* Common Event Queue Functions */

static ssize_t iommufd_eventq_fops_read(struct file *filep, char __user *buf,
					size_t count, loff_t *ppos)
{
	struct iommufd_eventq *eventq = filep->private_data;

	if (!eventq->ops || !eventq->ops->read)
		return -EOPNOTSUPP;
	return eventq->ops->read(eventq, buf, count, ppos);
}

static ssize_t iommufd_eventq_fops_write(struct file *filep,
					 const char __user *buf, size_t count,
					 loff_t *ppos)
{
	struct iommufd_eventq *eventq = filep->private_data;

	if (!eventq->ops || !eventq->ops->write)
		return -EOPNOTSUPP;
	return eventq->ops->write(eventq, buf, count, ppos);
}

static __poll_t iommufd_eventq_fops_poll(struct file *filep,
					 struct poll_table_struct *wait)
{
	struct iommufd_eventq *eventq = filep->private_data;
	__poll_t pollflags = EPOLLOUT;

	poll_wait(filep, &eventq->wait_queue, wait);
	mutex_lock(&eventq->mutex);
	if (!list_empty(&eventq->deliver))
		pollflags |= EPOLLIN | EPOLLRDNORM;
	mutex_unlock(&eventq->mutex);

	return pollflags;
}

static int iommufd_eventq_fops_release(struct inode *inode, struct file *filep)
{
	struct iommufd_eventq *eventq = filep->private_data;

	refcount_dec(&eventq->obj.users);
	iommufd_ctx_put(eventq->ictx);
	return 0;
}

static const struct file_operations iommufd_eventq_fops = {
	.owner		= THIS_MODULE,
	.open		= nonseekable_open,
	.read		= iommufd_eventq_fops_read,
	.write		= iommufd_eventq_fops_write,
	.poll		= iommufd_eventq_fops_poll,
	.release	= iommufd_eventq_fops_release,
};

static int iommufd_eventq_init(struct iommufd_eventq *eventq, char *name,
			       struct iommufd_ctx *ictx, int *out_fdno,
			       const struct iommufd_eventq_ops *ops)
{
	int fdno;

	eventq->ops = ops;
	eventq->ictx = ictx;
	mutex_init(&eventq->mutex);
	INIT_LIST_HEAD(&eventq->deliver);
	init_waitqueue_head(&eventq->wait_queue);

	eventq->filep =
		anon_inode_getfile(name, &iommufd_eventq_fops, eventq, O_RDWR);
	if (IS_ERR(eventq->filep))
		return PTR_ERR(eventq->filep);

	fdno = get_unused_fd_flags(O_CLOEXEC);
	if (fdno < 0) {
		fput(eventq->filep);
		return fdno;
	}

	iommufd_ctx_get(eventq->ictx);
	refcount_inc(&eventq->obj.users);
	if (out_fdno)
		*out_fdno = fdno;
	return 0;
}

int iommufd_eventq_iopf_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommu_fault_alloc *cmd = ucmd->cmd;
	struct iommufd_eventq_iopf *eventq_iopf;
	int fdno;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	eventq_iopf = __iommufd_object_alloc(
		ucmd->ictx, eventq_iopf, IOMMUFD_OBJ_EVENTQ_IOPF, common.obj);
	if (IS_ERR(eventq_iopf))
		return PTR_ERR(eventq_iopf);

	xa_init_flags(&eventq_iopf->response, XA_FLAGS_ALLOC1);

	rc = iommufd_eventq_init(&eventq_iopf->common, "[iommufd-pgfault]",
				 ucmd->ictx, &fdno, &iommufd_eventq_iopf_ops);
	if (rc)
		goto out_abort;

	cmd->out_fault_id = eventq_iopf->common.obj.id;
	cmd->out_fault_fd = fdno;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_put_fdno;
	iommufd_object_finalize(ucmd->ictx, &eventq_iopf->common.obj);

	fd_install(fdno, eventq_iopf->common.filep);

	return 0;
out_put_fdno:
	put_unused_fd(fdno);
	fput(eventq_iopf->common.filep);
	refcount_dec(&eventq_iopf->common.obj.users);
	iommufd_ctx_put(eventq_iopf->common.ictx);
out_abort:
	iommufd_object_abort_and_destroy(ucmd->ictx, &eventq_iopf->common.obj);

	return rc;
}

int iommufd_eventq_virq_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommu_virq_alloc *cmd = ucmd->cmd;
	struct iommufd_eventq_virq *eventq_virq;
	struct iommufd_viommu *viommu;
	int fdno;
	int rc;

	if (cmd->flags || cmd->type == IOMMU_VIRQ_TYPE_NONE)
		return -EOPNOTSUPP;

	viommu = iommufd_get_viommu(ucmd, cmd->viommu_id);
	if (IS_ERR(viommu))
		return PTR_ERR(viommu);
	down_write(&viommu->virqs_rwsem);

	if (iommufd_viommu_find_eventq_virq(viommu, cmd->type)) {
		rc = -EEXIST;
		goto out_unlock_virqs;
	}

	eventq_virq = __iommufd_object_alloc(
		ucmd->ictx, eventq_virq, IOMMUFD_OBJ_EVENTQ_VIRQ, common.obj);
	if (IS_ERR(eventq_virq)) {
		rc = PTR_ERR(eventq_virq);
		goto out_unlock_virqs;
	}

	eventq_virq->viommu = viommu;
	eventq_virq->type = cmd->type;
	refcount_inc(&viommu->obj.users);
	list_add_tail(&eventq_virq->node, &viommu->virqs);

	eventq_virq->irq_wq = alloc_workqueue("viommu_irq/%d", WQ_UNBOUND, 0,
					      eventq_virq->common.obj.id);
	if (!eventq_virq->irq_wq) {
		rc = -ENOMEM;
		goto out_abort;
	}

	rc = iommufd_eventq_init(&eventq_virq->common, "[iommufd-viommu-irq]",
				 ucmd->ictx, &fdno, &iommufd_eventq_virq_ops);
	if (rc)
		goto out_abort;

	cmd->out_virq_id = eventq_virq->common.obj.id;
	cmd->out_virq_fd = fdno;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_put_fdno;

	iommufd_object_finalize(ucmd->ictx, &eventq_virq->common.obj);
	fd_install(fdno, eventq_virq->common.filep);
	goto out_unlock_virqs;
out_put_fdno:
	put_unused_fd(fdno);
	fput(eventq_virq->common.filep);
	refcount_dec(&eventq_virq->common.obj.users);
	iommufd_ctx_put(eventq_virq->common.ictx);
out_abort:
	iommufd_object_abort_and_destroy(ucmd->ictx, &eventq_virq->common.obj);
out_unlock_virqs:
	up_write(&viommu->virqs_rwsem);
	iommufd_put_object(ucmd->ictx, &viommu->obj);
	return rc;
}
