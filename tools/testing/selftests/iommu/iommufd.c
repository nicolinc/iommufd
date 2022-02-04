// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES */
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <assert.h>

#include "../kselftest_harness.h"

#define __EXPORTED_HEADERS__
#include <linux/iommufd.h>
#include "../../../../drivers/iommu/iommufd/iommufd_test.h"

static void *buffer;

static unsigned long PAGE_SIZE;
static unsigned long HUGEPAGE_SIZE;
static unsigned long BUFFER_SIZE;

#define MOCK_PAGE_SIZE (PAGE_SIZE / 2)

static unsigned long get_huge_page_size(void)
{
	char buf[80];
	int ret;
	int fd;

	fd = open("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size",
		  O_RDONLY);
	if (fd < 0)
		return 2 * 1024 * 1024;

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret <= 0 || ret == sizeof(buf))
		return 2 * 1024 * 1024;
	buf[ret] = 0;
	return strtoul(buf, NULL, 10);
}

static __attribute__((constructor)) void setup_sizes(void)
{
	int rc;

	PAGE_SIZE = sysconf(_SC_PAGE_SIZE);
	HUGEPAGE_SIZE = get_huge_page_size();

	BUFFER_SIZE = PAGE_SIZE * 16;
	rc = posix_memalign(&buffer, HUGEPAGE_SIZE, BUFFER_SIZE);
	assert(rc || buffer || (uintptr_t)buffer % HUGEPAGE_SIZE == 0);
}

/*
 * Have the kernel check the refcount on pages. I don't know why a freshly
 * mmap'd anon non-compound page starts out with a ref of 3
 */
#define check_refs(_ptr, _length, _refs)                                       \
	({                                                                     \
		struct iommu_test_cmd test_cmd = {                             \
			.size = sizeof(test_cmd),                              \
			.op = IOMMU_TEST_OP_MD_CHECK_REFS,                     \
			.check_refs = { .length = _length,                     \
					.uptr = (uintptr_t)(_ptr),             \
					.refs = _refs },                       \
		};                                                             \
		ASSERT_EQ(0,                                                   \
			  ioctl(self->fd,                                      \
				_IOMMU_TEST_CMD(IOMMU_TEST_OP_MD_CHECK_REFS),  \
				&test_cmd));                                   \
	})

/* Hack to make assertions more readable */
#define _IOMMU_TEST_CMD(x) IOMMU_TEST_CMD

#define EXPECT_ERRNO(expected_errno, cmd)                                      \
	({                                                                     \
		ASSERT_EQ(-1, cmd);                                            \
		EXPECT_EQ(expected_errno, errno);                              \
	})

FIXTURE(iommufd) {
	int fd;
};

FIXTURE_SETUP(iommufd) {
	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
}

FIXTURE_TEARDOWN(iommufd) {
	ASSERT_EQ(0, close(self->fd));
}

TEST_F(iommufd, simple_close)
{
}

TEST_F(iommufd, cmd_fail)
{
	struct iommu_destroy cmd = { .size = sizeof(cmd), .id = 0 };

	/* object id is invalid */
	EXPECT_ERRNO(ENOENT, ioctl(self->fd, IOMMU_DESTROY, &cmd));
	/* Bad pointer */
	EXPECT_ERRNO(EFAULT, ioctl(self->fd, IOMMU_DESTROY, NULL));
	/* Unknown ioctl */
	EXPECT_ERRNO(ENOTTY,
		     ioctl(self->fd, _IO(IOMMUFD_TYPE, IOMMUFD_CMD_BASE - 1),
			   &cmd));
}

TEST_F(iommufd, cmd_ex_fail)
{
	struct {
		struct iommu_destroy cmd;
		__u64 future;
	} cmd = { .cmd = { .size = sizeof(cmd), .id = 0 } };

	/* object id is invalid and command is longer */
	EXPECT_ERRNO(ENOENT, ioctl(self->fd, IOMMU_DESTROY, &cmd));
	/* future area is non-zero */
	cmd.future = 1;
	EXPECT_ERRNO(E2BIG, ioctl(self->fd, IOMMU_DESTROY, &cmd));
	/* Original command "works" */
	cmd.cmd.size = sizeof(cmd.cmd);
	EXPECT_ERRNO(ENOENT, ioctl(self->fd, IOMMU_DESTROY, &cmd));
	/* Short command fails */
	cmd.cmd.size = sizeof(cmd.cmd) - 1;
	EXPECT_ERRNO(EOPNOTSUPP, ioctl(self->fd, IOMMU_DESTROY, &cmd));
}

FIXTURE(iommufd_ioas) {
	int fd;
	uint32_t ioas_id;
	uint32_t domain_id;
	uint64_t base_iova;
};

FIXTURE_VARIANT(iommufd_ioas) {
	unsigned int mock_domains;
	unsigned int memory_limit;
};

FIXTURE_SETUP(iommufd_ioas) {
	struct iommu_test_cmd memlimit_cmd = {
		.size = sizeof(memlimit_cmd),
		.op = IOMMU_TEST_OP_SET_TEMP_MEMORY_LIMIT,
		.memory_limit = {.limit = variant->memory_limit},
	};
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};
	unsigned int i;

	if (!variant->memory_limit)
		memlimit_cmd.memory_limit.limit = 65536;

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	ASSERT_NE(0, alloc_cmd.out_ioas_id);
	self->ioas_id = alloc_cmd.out_ioas_id;

	ASSERT_EQ(0, ioctl(self->fd,
			   _IOMMU_TEST_CMD(IOMMU_TEST_OP_SET_TEMP_MEMORY_LIMIT),
			   &memlimit_cmd));

	for (i = 0; i != variant->mock_domains; i++) {
		struct iommu_test_cmd test_cmd = {
			.size = sizeof(test_cmd),
			.op = IOMMU_TEST_OP_MOCK_DOMAIN,
			.id = self->ioas_id,
		};

		ASSERT_EQ(0, ioctl(self->fd,
				   _IOMMU_TEST_CMD(IOMMU_TEST_OP_MOCK_DOMAIN),
				   &test_cmd));
		EXPECT_NE(0, test_cmd.id);
		self->domain_id = test_cmd.id;
		self->base_iova = MOCK_APERTURE_START;
	}
}

FIXTURE_TEARDOWN(iommufd_ioas) {
	struct iommu_test_cmd memlimit_cmd = {
		.size = sizeof(memlimit_cmd),
		.op = IOMMU_TEST_OP_SET_TEMP_MEMORY_LIMIT,
		.memory_limit = {.limit = 65536},
	};

	ASSERT_EQ(0, ioctl(self->fd,
			   _IOMMU_TEST_CMD(IOMMU_TEST_OP_SET_TEMP_MEMORY_LIMIT),
			   &memlimit_cmd));
	ASSERT_EQ(0, close(self->fd));

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	check_refs(buffer, BUFFER_SIZE, 0);
	ASSERT_EQ(0, close(self->fd));
}

FIXTURE_VARIANT_ADD(iommufd_ioas, no_domain) {
};

FIXTURE_VARIANT_ADD(iommufd_ioas, mock_domain) {
	.mock_domains = 1,
};

FIXTURE_VARIANT_ADD(iommufd_ioas, two_mock_domain) {
	.mock_domains = 2,
};

FIXTURE_VARIANT_ADD(iommufd_ioas, mock_domain_limit) {
	.mock_domains = 1,
	.memory_limit = 16,
};

TEST_F(iommufd_ioas, ioas_auto_destroy)
{
}

TEST_F(iommufd_ioas, ioas_destroy)
{
	struct iommu_destroy destroy_cmd = {
		.size = sizeof(destroy_cmd),
		.id = self->ioas_id,
	};

	if (self->domain_id) {
		/* IOAS cannot be freed while a domain is on it */
		EXPECT_ERRNO(EBUSY,
			     ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
	} else {
		/* Can allocate and manually free an IOAS table */
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
	}
}

TEST_F(iommufd_ioas, ioas_area_destroy)
{
	struct iommu_destroy destroy_cmd = {
		.size = sizeof(destroy_cmd),
		.id = self->ioas_id,
	};
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.ioas_id = self->ioas_id,
		.user_va = (uintptr_t)buffer,
		.length = PAGE_SIZE,
		.iova = self->base_iova,
	};

	/* Adding an area does not change ability to destroy */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	if (self->domain_id)
		EXPECT_ERRNO(EBUSY,
			     ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
	else
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
}

TEST_F(iommufd_ioas, ioas_area_auto_destroy)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.ioas_id = self->ioas_id,
		.user_va = (uintptr_t)buffer,
		.length = PAGE_SIZE,
	};
	int i;

	/* Can allocate and automatically free an IOAS table with many areas */
	for (i = 0; i != 10; i++) {
		map_cmd.iova = self->base_iova + i * PAGE_SIZE;
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	}
}

TEST_F(iommufd_ioas, area)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.length = PAGE_SIZE,
		.user_va = (uintptr_t)buffer,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
	};
	int i;

	/* Unmap fails if nothing is mapped */
	for (i = 0; i != 10; i++) {
		unmap_cmd.iova = i * PAGE_SIZE;
		EXPECT_ERRNO(ENOENT, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
					   &unmap_cmd));
	}

	/* Unmap works */
	for (i = 0; i != 10; i++) {
		map_cmd.iova = self->base_iova + i * PAGE_SIZE;
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	}
	for (i = 0; i != 10; i++) {
		unmap_cmd.iova = self->base_iova + i * PAGE_SIZE;
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
				   &unmap_cmd));
	}

	/* Split fails */
	map_cmd.length = PAGE_SIZE * 2;
	map_cmd.iova = self->base_iova + 16 * PAGE_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	unmap_cmd.iova = self->base_iova + 16 * PAGE_SIZE;
	EXPECT_ERRNO(ENOENT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap_cmd));
	unmap_cmd.iova = self->base_iova + 17 * PAGE_SIZE;
	EXPECT_ERRNO(ENOENT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap_cmd));

	/* Over map fails */
	map_cmd.length = PAGE_SIZE * 2;
	map_cmd.iova = self->base_iova + 16 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE;
	map_cmd.iova = self->base_iova + 16 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE;
	map_cmd.iova = self->base_iova + 17 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE * 2;
	map_cmd.iova = self->base_iova + 15 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE * 3;
	map_cmd.iova = self->base_iova + 15 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));

	/* unmap all works */
	unmap_cmd.iova = 0;
	unmap_cmd.length = UINT64_MAX;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap_cmd));
}

TEST_F(iommufd_ioas, area_auto_iova)
{
	struct iommu_test_cmd test_cmd = {
		.size = sizeof(test_cmd),
		.op = IOMMU_TEST_OP_ADD_RESERVED,
		.id = self->ioas_id,
		.add_reserved = { .start = PAGE_SIZE * 4,
				  .length = PAGE_SIZE * 100 },
	};
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
		.user_va = (uintptr_t)buffer,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
	};
	uint64_t iovas[10];
	int i;

	/* Simple 4k pages */
	for (i = 0; i != 10; i++) {
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
		iovas[i] = map_cmd.iova;
	}
	for (i = 0; i != 10; i++) {
		unmap_cmd.iova = iovas[i];
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
				   &unmap_cmd));
	}

	/* Kernel automatically aligns IOVAs properly */
	if (self->domain_id)
		map_cmd.user_va = (uintptr_t)buffer;
	else
		map_cmd.user_va = 1UL << 31;
	for (i = 0; i != 10; i++) {
		map_cmd.length = PAGE_SIZE * (i + 1);
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
		iovas[i] = map_cmd.iova;
		EXPECT_EQ(0, map_cmd.iova % (1UL << (ffs(map_cmd.length)-1)));
	}
	for (i = 0; i != 10; i++) {
		unmap_cmd.length = PAGE_SIZE * (i + 1);
		unmap_cmd.iova = iovas[i];
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
				   &unmap_cmd));
	}

	/* Avoids a reserved region */
	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_ADD_RESERVED),
			&test_cmd));
	for (i = 0; i != 10; i++) {
		map_cmd.length = PAGE_SIZE * (i + 1);
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
		iovas[i] = map_cmd.iova;
		EXPECT_EQ(0, map_cmd.iova % (1UL << (ffs(map_cmd.length)-1)));
		EXPECT_EQ(false,
			  map_cmd.iova > test_cmd.add_reserved.start &&
				  map_cmd.iova <
					  test_cmd.add_reserved.start +
						  test_cmd.add_reserved.length);
	}
	for (i = 0; i != 10; i++) {
		unmap_cmd.length = PAGE_SIZE * (i + 1);
		unmap_cmd.iova = iovas[i];
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
				   &unmap_cmd));
	}
}

TEST_F(iommufd_ioas, copy_area)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.length = PAGE_SIZE,
		.user_va = (uintptr_t)buffer,
	};
	struct iommu_ioas_pagetable_copy copy_cmd = {
		.size = sizeof(copy_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.dst_ioas_id = self->ioas_id,
		.src_ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
	};
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};

	map_cmd.iova = self->base_iova;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));

	/* Copy inside a single IOAS */
	copy_cmd.src_iova = self->base_iova;
	copy_cmd.dst_iova = self->base_iova + PAGE_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_COPY, &copy_cmd));

	/* Copy between IOAS's */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	ASSERT_NE(0, alloc_cmd.out_ioas_id);
	copy_cmd.src_iova = self->base_iova;
	copy_cmd.dst_iova = 0;
	copy_cmd.dst_ioas_id = alloc_cmd.out_ioas_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_COPY, &copy_cmd));
}

TEST_F(iommufd_ioas, iova_ranges)
{
	struct iommu_test_cmd test_cmd = {
		.size = sizeof(test_cmd),
		.op = IOMMU_TEST_OP_ADD_RESERVED,
		.id = self->ioas_id,
		.add_reserved = { .start = PAGE_SIZE, .length = PAGE_SIZE },
	};
	struct iommu_ioas_pagetable_iova_ranges *cmd = (void *)buffer;

	*cmd = (struct iommu_ioas_pagetable_iova_ranges){
		.size = BUFFER_SIZE,
		.ioas_id = self->ioas_id,
	};

	/* Range can be read */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, cmd));
	EXPECT_EQ(1, cmd->out_num_iovas);
	if (!self->domain_id) {
		EXPECT_EQ(0, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(SIZE_MAX, cmd->out_valid_iovas[0].last);
	} else {
		EXPECT_EQ(MOCK_APERTURE_START, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(MOCK_APERTURE_LAST, cmd->out_valid_iovas[0].last);
	}
	memset(cmd->out_valid_iovas, 0,
	       sizeof(cmd->out_valid_iovas[0]) * cmd->out_num_iovas);

	/* Buffer too small */
	cmd->size = sizeof(*cmd);
	EXPECT_ERRNO(EMSGSIZE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, cmd));
	EXPECT_EQ(1, cmd->out_num_iovas);
	EXPECT_EQ(0, cmd->out_valid_iovas[0].start);
	EXPECT_EQ(0, cmd->out_valid_iovas[0].last);

	/* 2 ranges */
	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_ADD_RESERVED),
			&test_cmd));
	cmd->size = BUFFER_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, cmd));
	if (!self->domain_id) {
		EXPECT_EQ(2, cmd->out_num_iovas);
		EXPECT_EQ(0, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(PAGE_SIZE - 1, cmd->out_valid_iovas[0].last);
		EXPECT_EQ(PAGE_SIZE * 2, cmd->out_valid_iovas[1].start);
		EXPECT_EQ(SIZE_MAX, cmd->out_valid_iovas[1].last);
	} else {
		EXPECT_EQ(1, cmd->out_num_iovas);
		EXPECT_EQ(MOCK_APERTURE_START, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(MOCK_APERTURE_LAST, cmd->out_valid_iovas[0].last);
	}
	memset(cmd->out_valid_iovas, 0,
	       sizeof(cmd->out_valid_iovas[0]) * cmd->out_num_iovas);

	/* Buffer too small */
	cmd->size = sizeof(*cmd) + sizeof(cmd->out_valid_iovas[0]);
	if (!self->domain_id) {
		EXPECT_ERRNO(EMSGSIZE,
			     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES,
				   cmd));
		EXPECT_EQ(2, cmd->out_num_iovas);
		EXPECT_EQ(0, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(PAGE_SIZE - 1, cmd->out_valid_iovas[0].last);
	} else {
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES,
				   cmd));
		EXPECT_EQ(1, cmd->out_num_iovas);
		EXPECT_EQ(MOCK_APERTURE_START, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(MOCK_APERTURE_LAST, cmd->out_valid_iovas[0].last);
	}
	EXPECT_EQ(0, cmd->out_valid_iovas[1].start);
	EXPECT_EQ(0, cmd->out_valid_iovas[1].last);
}

TEST_F(iommufd_ioas, access)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.ioas_id = self->ioas_id,
		.user_va = (uintptr_t)buffer,
		.length = BUFFER_SIZE,
		.iova = MOCK_APERTURE_START,
	};
	struct iommu_test_cmd access_cmd = {
		.size = sizeof(access_cmd),
		.op = IOMMU_TEST_OP_ACCESS_PAGES,
		.id = self->ioas_id,
		.access_pages = { .iova = MOCK_APERTURE_START,
				  .length = BUFFER_SIZE,
				  .uptr = (uintptr_t)buffer },
	};
	struct iommu_test_cmd mock_cmd = {
		.size = sizeof(mock_cmd),
		.op = IOMMU_TEST_OP_MOCK_DOMAIN,
		.id = self->ioas_id,
	};
	struct iommu_test_cmd check_map_cmd = {
		.size = sizeof(check_map_cmd),
		.op = IOMMU_TEST_OP_MD_CHECK_MAP,
		.check_map = { .iova = MOCK_APERTURE_START,
			       .length = BUFFER_SIZE,
			       .uptr = (uintptr_t)buffer },
	};
	struct iommu_destroy destroy_cmd = { .size = sizeof(destroy_cmd) };
	uint32_t id;

	/* Single map/unmap */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_ACCESS_PAGES),
			&access_cmd));
	destroy_cmd.id = access_cmd.access_pages.out_access_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));

	/* Double user */
	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_ACCESS_PAGES),
			&access_cmd));
	id = access_cmd.access_pages.out_access_id;
	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_ACCESS_PAGES),
			&access_cmd));
	destroy_cmd.id = access_cmd.access_pages.out_access_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
	destroy_cmd.id = id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));

	/* Add/remove a domain with a user */
	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_ACCESS_PAGES),
			&access_cmd));
	ASSERT_EQ(0, ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_MOCK_DOMAIN),
			   &mock_cmd));
	check_map_cmd.id = mock_cmd.id;
	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_MD_CHECK_MAP),
			&check_map_cmd));
	destroy_cmd.id = mock_cmd.id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
	destroy_cmd.id = access_cmd.access_pages.out_access_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
}

FIXTURE(iommufd_mock_domain) {
	int fd;
	uint32_t ioas_id;
	uint32_t domain_id;
	uint32_t domain_ids[2];
	int mmap_flags;
	size_t mmap_buf_size;
};

FIXTURE_VARIANT(iommufd_mock_domain) {
	unsigned int mock_domains;
	bool hugepages;
};

FIXTURE_SETUP(iommufd_mock_domain)
{
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};
	struct iommu_test_cmd test_cmd = {
		.size = sizeof(test_cmd),
		.op = IOMMU_TEST_OP_MOCK_DOMAIN,
	};
	unsigned int i;

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	ASSERT_NE(0, alloc_cmd.out_ioas_id);
	self->ioas_id = alloc_cmd.out_ioas_id;

	ASSERT_GE(ARRAY_SIZE(self->domain_ids), variant->mock_domains);

	for (i = 0; i != variant->mock_domains; i++) {
		test_cmd.id = self->ioas_id;
		ASSERT_EQ(0, ioctl(self->fd,
				   _IOMMU_TEST_CMD(IOMMU_TEST_OP_MOCK_DOMAIN),
				   &test_cmd));
		EXPECT_NE(0, test_cmd.id);
		self->domain_ids[i] = test_cmd.id;
	}
	self->domain_id = self->domain_ids[0];

	self->mmap_flags = MAP_SHARED | MAP_ANONYMOUS;
	self->mmap_buf_size = PAGE_SIZE * 8;
	if (variant->hugepages) {
		self->mmap_flags |= MAP_HUGETLB | MAP_POPULATE;
		self->mmap_buf_size = HUGEPAGE_SIZE * 2;
	}
}

FIXTURE_TEARDOWN(iommufd_mock_domain) {
	ASSERT_EQ(0, close(self->fd));

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	check_refs(buffer, BUFFER_SIZE, 0);
	ASSERT_EQ(0, close(self->fd));
}

FIXTURE_VARIANT_ADD(iommufd_mock_domain, one_domain){
	.mock_domains = 1,
	.hugepages = false,
};

FIXTURE_VARIANT_ADD(iommufd_mock_domain, two_domains){
	.mock_domains = 2,
	.hugepages = false,
};

FIXTURE_VARIANT_ADD(iommufd_mock_domain, one_domain_hugepage){
	.mock_domains = 1,
	.hugepages = true,
};

FIXTURE_VARIANT_ADD(iommufd_mock_domain, two_domains_hugepage){
	.mock_domains = 2,
	.hugepages = true,
};

/* Have the kernel check that the user pages made it to the iommu_domain */
#define check_mock_iova(_ptr, _iova, _length)                                  \
	({                                                                     \
		struct iommu_test_cmd check_map_cmd = {                        \
			.size = sizeof(check_map_cmd),                         \
			.op = IOMMU_TEST_OP_MD_CHECK_MAP,                      \
			.id = self->domain_id,                                 \
			.check_map = { .iova = _iova,                          \
				       .length = _length,                      \
				       .uptr = (uintptr_t)(_ptr) },            \
		};                                                             \
		ASSERT_EQ(0,                                                   \
			  ioctl(self->fd,                                      \
				_IOMMU_TEST_CMD(IOMMU_TEST_OP_MD_CHECK_MAP),   \
				&check_map_cmd));                              \
		if (self->domain_ids[1]) {                                     \
			check_map_cmd.id = self->domain_ids[1];                \
			ASSERT_EQ(0,                                           \
				  ioctl(self->fd,                              \
					_IOMMU_TEST_CMD(                       \
						IOMMU_TEST_OP_MD_CHECK_MAP),   \
					&check_map_cmd));                      \
		}                                                              \
	})

TEST_F(iommufd_mock_domain, basic)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
	};
	size_t buf_size = self->mmap_buf_size;
	uint8_t *buf;

	/* Simple one page map */
	map_cmd.user_va = (uintptr_t)buffer;
	map_cmd.length = PAGE_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	check_mock_iova(buffer, map_cmd.iova, map_cmd.length);

	buf = mmap(0, buf_size, PROT_READ | PROT_WRITE, self->mmap_flags, -1,
		   0);
	ASSERT_NE(MAP_FAILED, buf);

	/* EFAULT half way through mapping */
	ASSERT_EQ(0, munmap(buf + buf_size / 2, buf_size / 2));
	map_cmd.user_va = (uintptr_t)buf;
	map_cmd.length = buf_size;
	EXPECT_ERRNO(EFAULT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));

	/* EFAULT on first page */
	ASSERT_EQ(0, munmap(buf, buf_size / 2));
	EXPECT_ERRNO(EFAULT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
}

TEST_F(iommufd_mock_domain, all_aligns)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
	};
	size_t test_step =
		variant->hugepages ? (self->mmap_buf_size / 16) : MOCK_PAGE_SIZE;
	size_t buf_size = self->mmap_buf_size;
	unsigned int start;
	unsigned int end;
	uint8_t *buf;

	buf = mmap(0, buf_size, PROT_READ | PROT_WRITE, self->mmap_flags, -1, 0);
	ASSERT_NE(MAP_FAILED, buf);
	check_refs(buf, buf_size, 0);

	/*
	 * Map every combination of page size and alignment within a big region,
	 * less for hugepage case as it takes so long to finish.
	 */
	for (start = 0; start < buf_size; start += test_step) {
		map_cmd.user_va = (uintptr_t)buf + start;
		if (variant->hugepages)
			end = buf_size;
		else
			end = start + MOCK_PAGE_SIZE;
		for (; end < buf_size; end += MOCK_PAGE_SIZE) {
			map_cmd.length = end - start;
			ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP,
					   &map_cmd));
			check_mock_iova(buf + start, map_cmd.iova,
					map_cmd.length);
			check_refs(buf + start / PAGE_SIZE * PAGE_SIZE,
				   end / PAGE_SIZE * PAGE_SIZE -
					   start / PAGE_SIZE * PAGE_SIZE,
				   1);

			unmap_cmd.iova = map_cmd.iova;
			unmap_cmd.length = end - start;
			ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
					   &unmap_cmd));
		}
	}
	check_refs(buf, buf_size, 0);
	ASSERT_EQ(0, munmap(buf, buf_size));
}

TEST_F(iommufd_mock_domain, all_aligns_copy)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
	};
	struct iommu_test_cmd add_mock_pt = {
		.size = sizeof(add_mock_pt),
		.op = IOMMU_TEST_OP_MOCK_DOMAIN,
	};
	struct iommu_destroy destroy_cmd = {
		.size = sizeof(destroy_cmd),
	};
	size_t test_step =
		variant->hugepages ? self->mmap_buf_size / 16 : MOCK_PAGE_SIZE;
	size_t buf_size = self->mmap_buf_size;
	unsigned int start;
	unsigned int end;
	uint8_t *buf;

	buf = mmap(0, buf_size, PROT_READ | PROT_WRITE, self->mmap_flags, -1, 0);
	ASSERT_NE(MAP_FAILED, buf);
	check_refs(buf, buf_size, 0);

	/*
	 * Map every combination of page size and alignment within a big region,
	 * less for hugepage case as it takes so long to finish.
	 */
	for (start = 0; start < buf_size; start += test_step) {
		map_cmd.user_va = (uintptr_t)buf + start;
		if (variant->hugepages)
			end = buf_size;
		else
			end = start + MOCK_PAGE_SIZE;
		for (; end < buf_size; end += MOCK_PAGE_SIZE) {
			unsigned int old_id;

			map_cmd.length = end - start;
			ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP,
					   &map_cmd));

			/* Add and destroy a domain while the area exists */
			add_mock_pt.id = self->ioas_id;
			ASSERT_EQ(0, ioctl(self->fd,
					   _IOMMU_TEST_CMD(
						   IOMMU_TEST_OP_MOCK_DOMAIN),
					   &add_mock_pt));
			old_id = self->domain_ids[1];
			self->domain_ids[1] = add_mock_pt.id;

			check_mock_iova(buf + start, map_cmd.iova,
					map_cmd.length);
			check_refs(buf + start / PAGE_SIZE * PAGE_SIZE,
				   end / PAGE_SIZE * PAGE_SIZE -
					   start / PAGE_SIZE * PAGE_SIZE,
				   1);

			destroy_cmd.id = add_mock_pt.id;
			ASSERT_EQ(0,
				  ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
			self->domain_ids[1] = old_id;

			unmap_cmd.iova = map_cmd.iova;
			unmap_cmd.length = end - start;
			ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
					   &unmap_cmd));
		}
	}
	check_refs(buf, buf_size, 0);
	ASSERT_EQ(0, munmap(buf, buf_size));
}

TEST_F(iommufd_mock_domain, user_copy)
{
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.ioas_id = self->ioas_id,
		.user_va = (uintptr_t)buffer,
		.length = BUFFER_SIZE,
		.iova = MOCK_APERTURE_START,
	};
	struct iommu_test_cmd access_cmd = {
		.size = sizeof(access_cmd),
		.op = IOMMU_TEST_OP_ACCESS_PAGES,
		.id = self->ioas_id,
		.access_pages = { .iova = MOCK_APERTURE_START,
				  .length = BUFFER_SIZE,
				  .uptr = (uintptr_t)buffer },
	};
	struct iommu_ioas_pagetable_copy copy_cmd = {
		.size = sizeof(copy_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.dst_ioas_id = self->ioas_id,
		.src_iova = MOCK_APERTURE_START,
		.dst_iova = MOCK_APERTURE_START,
		.length = BUFFER_SIZE,
	};
	struct iommu_destroy destroy_cmd = { .size = sizeof(destroy_cmd) };

	/* Pin the pages in an IOAS with no domains then copy to an IOAS with domains */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	map_cmd.ioas_id = alloc_cmd.out_ioas_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	access_cmd.id = alloc_cmd.out_ioas_id;

	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_ACCESS_PAGES),
			&access_cmd));
	copy_cmd.src_ioas_id = alloc_cmd.out_ioas_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_COPY, &copy_cmd));
	check_mock_iova(buffer, map_cmd.iova, BUFFER_SIZE);

	destroy_cmd.id = access_cmd.access_pages.out_access_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
	destroy_cmd.id = alloc_cmd.out_ioas_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
}

/* FIXME use fault injection to test memory failure paths */

TEST_HARNESS_MAIN
