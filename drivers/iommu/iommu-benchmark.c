// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES.
 *
 * IOMMU Map and Unmap Benchmark Test Program
 */

#define pr_fmt(fmt) "iommu_benchmark: " fmt

#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched/clock.h>

#define MAP	0
#define UNMAP	1

enum {
	TEST_MAP = 0,
	TEST_MAP_SG,
	TEST_ALLOC,
	TEST_MAX,
};

static u32 iters = 10;
static u32 threads = 1;
static u32 test_id = TEST_MAP_SG;
static size_t size, size_kb = 1;

static const char *header_str[2][TEST_MAX] = {
	[MAP] = {
		[TEST_MAP] = "Map",
		[TEST_MAP_SG] = "SG Map",
		[TEST_ALLOC] = "Alloc",
	},
	[UNMAP] = {
		[TEST_MAP] = "Unmap",
		[TEST_MAP_SG] = "SG Unmap",
		[TEST_ALLOC] = "Free",
	},
};

struct time_struct {
	u64 sum;
	s64 min;
	u64 max;
	u64 iter;
};

struct test_thread {
	struct device *dev;
	struct task_struct *task;
	struct time_struct times[2];
	atomic_t *finished;
};

static void time_init(struct time_struct *d) {
	memset(d, 0, sizeof(*d));
	d->min = S64_MAX;
}

static u64 time_average(struct time_struct *d) {
	if (d->iter == 0)
		return 0;
	return d->sum / d->iter;
}

static void time_add(struct time_struct *d, u64 time) {
	if (d->iter == 0) {
		d->min = time;
		d->max = time;
	}

	if (time < d->min)
		d->min = time;

	if (time > d->max)
		d->max = time;

	d->sum += time;
	d->iter += 1;
}

static void time_merge(struct time_struct *dst, struct time_struct *src)
{
	dst->sum += src->sum;
	dst->iter += src->iter;
	dst->min = min(dst->min, src->min);
	dst->max = max(dst->max, src->max);
}

static int iommu_map_benchmark(void *data)
{
	struct test_thread *test = data;
	struct device *dev = test->dev;
	dma_addr_t iova;
	int ret = 0;
	int i;

	for (i = 0; i < iters; i++) {
		u64 start, end;
		void *buf;

		buf = kzalloc(size, GFP_KERNEL | GFP_DMA);
		if (!buf) {
			ret = -ENOMEM;
			goto out;
		}

		start = local_clock();
		iova = dma_map_single(dev, buf, size, DMA_FROM_DEVICE);
		end = local_clock();

		if (dma_mapping_error(dev, iova)) {
			ret = -ENOMEM;
			kfree(buf);
			goto out;
		}
		time_add(&test->times[MAP], end - start);

		start = local_clock();
		dma_unmap_single(dev, iova, size, DMA_FROM_DEVICE);
		time_add(&test->times[UNMAP], local_clock() - start);

		kfree(buf);
	}
out:
	atomic_inc(test->finished);
	return ret;
}

static int iommu_map_sg_benchmark(void *data)
{
	unsigned long npages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct test_thread *test = data;
	struct device *dev = test->dev;
	struct page **pages;
	int ret = 0;
	int i;

	pages = kcalloc(npages, sizeof(*pages), GFP_KERNEL);
	if (!pages) {
		atomic_inc(test->finished);
		return -ENOMEM;
	}

	for (i = 0; i < npages; i++) {
		pages[i] = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
		if (!pages[i]) {
			ret = -ENOMEM;
			goto out_free_pages;
		}
	}

	for (i = 0; i < iters; i++) {
		struct sg_table *sgt;
		unsigned int nents;
		u64 start, end;

		sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
		if (!sgt) {
			ret = -ENOMEM;
			goto out_free_pages;
		}

		ret = sg_alloc_table_from_pages(sgt, pages, npages, 0,
						size, GFP_KERNEL);
		if (ret) {
			ret = -ENOMEM;
			kfree(sgt);
			goto out_free_pages;
		}

		start = local_clock();
		nents = dma_map_sg_attrs(dev, sgt->sgl, sgt->nents,
					 DMA_FROM_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
		end = local_clock();

		if (!nents) {
			ret = -ENOMEM;
			sg_free_table(sgt);
			kfree(sgt);
			goto out_free_pages;
		}

		time_add(&test->times[MAP], end - start);

		start = local_clock();
		dma_unmap_sg_attrs(dev, sgt->sgl, sgt->nents,
				   DMA_FROM_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
		time_add(&test->times[UNMAP], local_clock() - start);

		sg_free_table(sgt);
		kfree(sgt);
	}
out_free_pages:
	for (i = 0; i < npages; i++) {
		if (pages[i])
			__free_pages(pages[i], 0);
	}
	kfree(pages);
	atomic_inc(test->finished);
	return ret;
}

static int iommu_alloc_benchmark(void *data)
{
	struct test_thread *test = data;
	struct device *dev = test->dev;
	int ret = 0;
	int i;

	for (i = 0; i < iters; i++) {
		dma_addr_t iova;
		u64 start, end;
		void *buf;

		start = local_clock();
		buf = dma_alloc_attrs(dev, size, &iova, GFP_KERNEL, 0);
		end = local_clock();

		if (dma_mapping_error(dev, iova)) {
			ret = -ENOMEM;
			goto out;
		}
		time_add(&test->times[MAP], end - start);

		start = local_clock();
		dma_free_attrs(dev, size, buf, iova, 0);
		time_add(&test->times[UNMAP], local_clock() - start);
	}

out:
	atomic_inc(test->finished);
	return ret;
}

static const int (*test_fn[])(void *) = {
	[TEST_MAP]	= iommu_map_benchmark,
	[TEST_MAP_SG]	= iommu_map_sg_benchmark,
	[TEST_ALLOC]	= iommu_alloc_benchmark,
};

static int start_show(struct seq_file *file, void *data)
{
	struct device *dev = file->private;
	struct time_struct times[2];
	struct test_thread *tests;
	atomic_t finished;
	int i, ret;

	if (WARN_ON(!dev))
		return -ENODEV;
	if (test_id > ARRAY_SIZE(test_fn))
		return -EINVAL;

	size = size_kb * SZ_1K;
	tests = kcalloc(threads, sizeof(*tests), GFP_KERNEL);
	if (!tests)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(times); i++)
		time_init(&times[i]);

	atomic_set(&finished, 0);
	for (i = 0; i < threads; i++) {
		tests[i].dev = dev;
		tests[i].finished = &finished;
		tests[i].task = kthread_create(test_fn[test_id], &tests[i],
					       "%s", "iommu_test");
		if (IS_ERR(tests[i].task))
			goto out_free;
	}
	for (i = 0; i < threads; i++)
		wake_up_process(tests[i].task);

	while (atomic_read(&finished) < threads)
		usleep_range(50, 200);

	for (i = 0; i < threads; i++) {
		time_merge(&times[MAP], &tests[i].times[MAP]);
		time_merge(&times[UNMAP], &tests[i].times[UNMAP]);
	}

	seq_printf(file, "%10s  %9s  %10s  %7s  %13s  %13s  %13s\n",
		   "Test", "Size (KB)", "Iterations", "Threads",
		   "Min Time (ns)", "Max Time (ns)", "Avg Time (ns)");
	for (i = 0; i < ARRAY_SIZE(times); i++) {
		seq_printf(file,
			   "%10s  %9ld  %10d  %7d  %13llu  %13llu  %13llu\n",
			   header_str[i][test_id], size_kb, iters, threads,
			   times[i].min, times[i].max,
			   time_average(&times[i]));
	}
out_free:
	kfree(tests);
	return ret;
}
DEFINE_SHOW_ATTRIBUTE(start);

static struct dentry *benchmark_dir;
extern struct dentry *iommu_debugfs_dir;

void iommu_benchmark_init(struct device *dev)
{
	if (!iommu_debugfs_dir || benchmark_dir)
		return;

	benchmark_dir = debugfs_create_dir("benchmark", iommu_debugfs_dir);
	if (!benchmark_dir)
		return;

	debugfs_create_u32("iters", 0600, benchmark_dir, &iters);
	debugfs_create_u32("threads", 0600, benchmark_dir, &threads);
	debugfs_create_u32("test_id", 0600, benchmark_dir, &test_id);
	debugfs_create_size_t("size_kb", 0600, benchmark_dir, &size_kb);
	debugfs_create_file("start", 0600, benchmark_dir, dev, &start_fops);

	pr_info("loaded iommu_benchmark\n");
}
EXPORT_SYMBOL_GPL(iommu_benchmark_init);
