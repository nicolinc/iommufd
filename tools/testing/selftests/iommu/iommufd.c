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
#include <linux/vfio.h>
#include "../../../../drivers/iommu/iommufd/iommufd_test.h"

static void *buffer;

static unsigned long PAGE_SIZE;
static unsigned long HUGEPAGE_SIZE;
static unsigned long BUFFER_SIZE;

#define get_page_size(hugepage) (hugepage) ? HUGEPAGE_SIZE : PAGE_SIZE

#define SYS_HPAGE_PMD_SIZE "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size"

static unsigned long get_huge_page_size(void)
{
	int fd = open(SYS_HPAGE_PMD_SIZE, O_RDONLY);
	unsigned long val;
	char buf[80 + 1];
	int ret;

	if (fd < 0) {
		/* Assuming 2 MiB size */
		return 2 * 1024 * 1024u;
	}

	ret = pread(fd, buf, sizeof(buf) - 1, 0);
	if (ret <= 0) {
		/* Assuming 2 MiB size */
		val = 2 * 1024 * 1024u;
	} else {
		buf[ret] = 0;
		val = strtoul(buf, NULL, 10);
	}
	close(fd);

	return val;
}

static __attribute__((constructor)) void setup_sizes(void)
{
	int rc;

	PAGE_SIZE = sysconf(_SC_PAGE_SIZE);
	HUGEPAGE_SIZE = get_huge_page_size();

	/* Set BUFFER_SIZE to x8 as tests would cover */
	BUFFER_SIZE = HUGEPAGE_SIZE * 8;

	rc = posix_memalign(&buffer, BUFFER_SIZE, BUFFER_SIZE);
	assert(rc || (uintptr_t)buffer % HUGEPAGE_SIZE == 0);
}

#define get_mock_page_size(hugepage) \
	(hugepage) ? (HUGEPAGE_SIZE / 2) : (PAGE_SIZE / 2)

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
};

FIXTURE_SETUP(iommufd_ioas) {
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};
	unsigned int i;

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	ASSERT_NE(0, alloc_cmd.out_ioas_id);
	self->ioas_id = alloc_cmd.out_ioas_id;

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
	ASSERT_EQ(0, close(self->fd));

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	check_refs(buffer, BUFFER_SIZE, 0);
	ASSERT_EQ(0, close(self->fd));
}

FIXTURE_VARIANT_ADD(iommufd_ioas, no_domain) {
};

FIXTURE_VARIANT_ADD(iommufd_ioas, mock_domain) {
	.mock_domains = 1
};

FIXTURE_VARIANT_ADD(iommufd_ioas, two_mock_domain) {
	.mock_domains = 2
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
	int fd_hugepages;
	uint32_t ioas_id;
	uint32_t domain_id;
	uint32_t domain_ids[2];
	uint32_t nr_hugepages;
};

FIXTURE_VARIANT(iommufd_mock_domain) {
	unsigned long memory_limit;
	unsigned int mock_domains;
	bool hugepages;
};

/* Expand nr_hugepages setting if it is not sufficient to run tests */
int init_nr_hugepages_if_lt(char *min, int *fd_hugepages, uint32_t *nr_hugepages)
{
	char nr[10] = {0};
	int fd, ret;

	*fd_hugepages = -1;
	*nr_hugepages = 0;

	fd = open("/proc/sys/vm/nr_hugepages", O_RDWR | O_NONBLOCK);
	if (fd < 0)
		return fd;

	*fd_hugepages = fd;
	ret = read(fd, nr, sizeof(nr));
	if (ret <= 0)
		goto err;

	if (atoi(nr) < atoi(min)) {
		lseek(fd, 0, SEEK_SET);
		ret = write(fd, min, strlen(min));
		if (ret != strlen(min))
			goto err;
		*nr_hugepages = atoi(nr);
	}

	close (fd);
	return 0;

err:
	*fd_hugepages = -1;
	*nr_hugepages = 0;
	close(fd);
	return -1;
}

int restore_nr_hugepges(int fd, uint32_t nr_hugepages)
{
	if (fd != -1) {
		int fd = open("/proc/sys/vm/nr_hugepages", O_RDWR | O_NONBLOCK);
		char nr[10] = {0};
		int ret;

		lseek(fd, 0, SEEK_SET);
		sprintf(nr, "%d", nr_hugepages);
		ret = write(fd, nr, strlen(nr));
		close(fd);
		if (ret != strlen(nr))
			return -1;
	}

	return 0;
}

FIXTURE_SETUP(iommufd_mock_domain)
{
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};
	struct iommu_test_cmd test_cmd = {
		.size = sizeof(test_cmd),
		.op = IOMMU_TEST_OP_MOCK_DOMAIN,
		.memory_limit = variant->memory_limit,
	};
	unsigned int i;

	ASSERT_EQ(0, init_nr_hugepages_if_lt("32", &self->fd_hugepages,
					     &self->nr_hugepages));

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
}

FIXTURE_TEARDOWN(iommufd_mock_domain) {
	ASSERT_EQ(0, close(self->fd));

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	check_refs(buffer, BUFFER_SIZE, 0);
	ASSERT_EQ(0, close(self->fd));

	ASSERT_EQ(0, restore_nr_hugepges(self->fd_hugepages,
					 self->nr_hugepages));
}

FIXTURE_VARIANT_ADD(iommufd_mock_domain, one_domain){
	.memory_limit = 65536,
	.mock_domains = 1,
	.hugepages = false,
};

FIXTURE_VARIANT_ADD(iommufd_mock_domain, two_domains){
	.memory_limit = 65536,
	.mock_domains = 2,
	.hugepages = false,
};

FIXTURE_VARIANT_ADD(iommufd_mock_domain, one_domain_hugepage){
	.memory_limit = 65536,
	.mock_domains = 1,
	.hugepages = true,
};

FIXTURE_VARIANT_ADD(iommufd_mock_domain, one_domain_hugepage_half_limit){
	.memory_limit = 32768,
	.mock_domains = 1,
	.hugepages = true,
};

FIXTURE_VARIANT_ADD(iommufd_mock_domain, two_domains_hugepage){
	.memory_limit = 65536,
	.mock_domains = 2,
	.hugepages = true,
};

FIXTURE_VARIANT_ADD(iommufd_mock_domain, two_domains_hugepage_half_limit){
	.memory_limit = 32768,
	.mock_domains = 2,
	.hugepages = true,
};

/* check if the user addr is backed by hugepages */
#define PAGEMAP_PRESENT	(1ULL << 63)
#define PAGEMAP_PFN	((1ULL << 55) - 1)
#define KPAGEFLAGS_HUGE	(1ULL << 15)

static bool is_backed_by_huge(void *addr)
{
	unsigned long pfn = (unsigned long)addr / PAGE_SIZE;
	uint64_t entry;
	uint64_t flags;
	int fd, ret;

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0)
		return 0;

	ret = pread(fd, &entry, sizeof(entry), pfn * sizeof(entry));
	if (ret != sizeof(entry)) {
		close(fd);
		return 0;
	}

	close(fd);

	pfn = entry & PAGEMAP_PRESENT ? entry & PAGEMAP_PFN : 0;
	if (!pfn)
		return 0;

	fd = open("/proc/kpageflags", O_RDONLY);
	if (fd < 0)
		return 0;

	ret = pread(fd, &flags, sizeof(flags), sizeof(flags) * pfn);
	if (ret != sizeof(flags))
		return 0;

	return !!(flags & KPAGEFLAGS_HUGE);
}

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

#define mock_domain_basic(vfio_compact, map_cmd, user_va, iova, length)        \
	({                                                                     \
		unsigned long IOCTL_CMD_MAP = vfio_compact ?                   \
					      VFIO_IOMMU_MAP_DMA :             \
					      IOMMU_IOAS_PAGETABLE_MAP;        \
		size_t page_size = get_page_size(variant->hugepages);          \
		int flags = MAP_SHARED | MAP_ANONYMOUS;                        \
		int prot = PROT_READ | PROT_WRITE;                             \
		uint8_t *buf;                                                  \
		/* vfio_compact must provide iova for FIXED_IOVA */            \
		if (vfio_compact)                                              \
			*iova = MOCK_APERTURE_START;                           \
		*user_va = (uintptr_t)buffer;                                  \
		*length = page_size;                                           \
		/* Simple one page map */                                      \
		ASSERT_EQ(0, ioctl(self->fd, IOCTL_CMD_MAP, map_cmd));         \
		check_mock_iova(buffer, *iova, page_size);                     \
		/* Also MAP_POPULATE for pageflag check */                     \
		if (variant->hugepages)                                        \
			flags |= MAP_HUGETLB | MAP_POPULATE;                   \
		/* EFAULT half way through mapping */                          \
		buf = mmap(0, page_size * 8, prot, flags, -1, 0);              \
		ASSERT_NE(MAP_FAILED, buf);                                    \
		/* Ensure buf is backed by hugepages */                        \
		if (variant->hugepages)                                        \
			ASSERT_EQ(1, is_backed_by_huge(buf));                  \
		ASSERT_EQ(0, munmap(buf + page_size * 4, page_size * 4));      \
		if (vfio_compact)                                              \
			*iova += *length;                                      \
		*user_va = (uintptr_t)buf;                                     \
		*length = page_size * 8;                                       \
		EXPECT_ERRNO(EFAULT,                                           \
			     ioctl(self->fd, IOCTL_CMD_MAP, map_cmd));         \
		/* EFAULT on first page */                                     \
		ASSERT_EQ(0, munmap(buf, page_size * 4));                      \
		if (vfio_compact)                                              \
			*iova += *length;                                      \
		EXPECT_ERRNO(EFAULT,                                           \
			     ioctl(self->fd, IOCTL_CMD_MAP, map_cmd));         \
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
	__u64 *user_va = &map_cmd.user_va;
	__u64 *length = &map_cmd.length;
	__u64 *iova = &map_cmd.iova;

	mock_domain_basic(false, &map_cmd, user_va, iova, length);
}

#define mock_domain_all_aligns(vfio_compact, map_cmd, unmap_cmd, user_va,      \
			       map_iova, map_length, unmap_iova, unmap_length) \
	({                                                                     \
		unsigned long IOCTL_CMD_UNMAP = vfio_compact ?                 \
					      VFIO_IOMMU_UNMAP_DMA :           \
					      IOMMU_IOAS_PAGETABLE_UNMAP;      \
		unsigned long IOCTL_CMD_MAP = vfio_compact ?                   \
					      VFIO_IOMMU_MAP_DMA :             \
					      IOMMU_IOAS_PAGETABLE_MAP;        \
		int flags = MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE;         \
		size_t mock_page_size = get_mock_page_size(variant->hugepages);\
		size_t page_size = get_page_size(variant->hugepages);          \
		size_t buf_size = page_size * 8;                               \
		unsigned int start, end;                                       \
		uint8_t *buf;                                                  \
		if (variant->hugepages)                                        \
			flags |= MAP_HUGETLB;                                  \
		buf = mmap(0, buf_size, PROT_READ | PROT_WRITE, flags, -1, 0); \
		ASSERT_NE(MAP_FAILED, buf);                                    \
		check_refs(buf, buf_size, 0);                                  \
		/* Ensure buf is backed by hugepages */                        \
		if (variant->hugepages)                                        \
			ASSERT_EQ(1, is_backed_by_huge(buf));                  \
		/* vfio_compact must provide iova for FIXED_IOVA */            \
		if (vfio_compact)                                              \
			*map_iova = MOCK_APERTURE_START;                       \
		/*                                                             \
		 * Map every combination of page size and                      \
		 * alignment within a big region                               \
		 */                                                            \
		for (start = 0; start != buf_size - mock_page_size;            \
		     start += mock_page_size) {                                \
			*user_va = (uintptr_t)buf + start;                     \
			for (end = start + mock_page_size; end <= buf_size;    \
			     end += mock_page_size) {                          \
				*map_length = end - start;                     \
				ASSERT_EQ(0, ioctl(self->fd, IOCTL_CMD_MAP,    \
						   &map_cmd));                 \
				check_mock_iova(buf + start, *map_iova,        \
						*map_length);                  \
				check_refs(buf + start / page_size * page_size,\
					   end / page_size * page_size -       \
					   start / page_size * page_size,      \
					   1);                                 \
				*unmap_iova = *map_iova;                       \
				*unmap_length = end - start;                   \
				ASSERT_EQ(0, ioctl(self->fd, IOCTL_CMD_UNMAP,  \
						   &unmap_cmd));               \
			}                                                      \
			if (vfio_compact)                                      \
				*map_iova += mock_page_size;                   \
		}                                                              \
		check_refs(buf, buf_size, 0);                                  \
		ASSERT_EQ(0, munmap(buf, buf_size));                           \
	})

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
	__u64 *unmap_length = &unmap_cmd.length;
	__u64 *unmap_iova = &unmap_cmd.iova;
	__u64 *map_length = &map_cmd.length;
	__u64 *map_iova = &map_cmd.iova;
	__u64 *user_va = &map_cmd.user_va;

	mock_domain_all_aligns(false, map_cmd, unmap_cmd, user_va,
			       map_iova, map_length, unmap_iova, unmap_length);
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
		.memory_limit = variant->memory_limit,
	};
	struct iommu_destroy destroy_cmd = {
		.size = sizeof(destroy_cmd),
	};
	int flags = MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE;
	size_t mock_page_size = get_mock_page_size(variant->hugepages);
	size_t page_size = get_page_size(variant->hugepages);
	size_t buf_size = page_size * 8;
	unsigned int start;
	unsigned int end;
	uint8_t *buf;

	if (variant->hugepages)
		flags |= MAP_HUGETLB;
	buf = mmap(0, buf_size, PROT_READ | PROT_WRITE, flags, -1, 0);
	ASSERT_NE(MAP_FAILED, buf);
	check_refs(buf, buf_size, 0);

	/* Ensure buf is backed by hugepages */
	if (variant->hugepages)
		ASSERT_EQ(1, is_backed_by_huge(buf));

	/* Map every combination and copy into a newly added domain */
	for (start = 0; start != buf_size - mock_page_size;
	     start += mock_page_size) {
		map_cmd.user_va = (uintptr_t)buf + start;
		for (end = start + mock_page_size; end <= buf_size;
		     end += mock_page_size) {
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
			check_refs(buf + start / page_size * page_size,
				   end / page_size * page_size -
					   start / page_size * page_size,
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

FIXTURE(vfio_compact_mock_domain) {
	int fd;
	int fd_hugepages;
	uint32_t domain_id;
	uint32_t domain_ids[2];
	uint32_t nr_hugepages;
};

FIXTURE_VARIANT(vfio_compact_mock_domain) {
	unsigned int mock_domains;
	bool hugepages;
};

FIXTURE_VARIANT_ADD(vfio_compact_mock_domain, one_domain){
	.mock_domains = 1,
	.hugepages = false,
};

FIXTURE_VARIANT_ADD(vfio_compact_mock_domain, one_domain_hugepage){
	.mock_domains = 1,
	.hugepages = true,
};

FIXTURE_VARIANT_ADD(vfio_compact_mock_domain, two_domain){
	.mock_domains = 2,
	.hugepages = false,
};

FIXTURE_VARIANT_ADD(vfio_compact_mock_domain, two_domain_hugepage){
	.mock_domains = 2,
	.hugepages = true,
};

FIXTURE_SETUP(vfio_compact_mock_domain) {
	struct iommu_test_cmd test_cmd = {
		.size = sizeof(test_cmd),
		.op = IOMMU_TEST_OP_MOCK_DOMAIN,
		.id = 0,
	};
	int i;

	ASSERT_EQ(0, init_nr_hugepages_if_lt("32", &self->fd_hugepages,
					     &self->nr_hugepages));

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);

	ASSERT_EQ(VFIO_API_VERSION, ioctl(self->fd, VFIO_GET_API_VERSION));
	ASSERT_EQ(1, ioctl(self->fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU));

	ASSERT_GE(ARRAY_SIZE(self->domain_ids), variant->mock_domains);

	for (i = 0; i != variant->mock_domains; i++) {
		test_cmd.fd = self->fd;
		ASSERT_EQ(0, ioctl(self->fd,
				   _IOMMU_TEST_CMD(IOMMU_TEST_OP_MOCK_DOMAIN),
				   &test_cmd));
		EXPECT_NE(0, test_cmd.id);
		self->domain_ids[i] = test_cmd.id;
	}
	self->domain_id = self->domain_ids[0];

	ASSERT_EQ(0, ioctl(self->fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU));
}

FIXTURE_TEARDOWN(vfio_compact_mock_domain) {
	ASSERT_EQ(0, close(self->fd));

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	check_refs(buffer, BUFFER_SIZE, 0);
	ASSERT_EQ(0, close(self->fd));

	ASSERT_EQ(0, restore_nr_hugepges(self->fd_hugepages,
					 self->nr_hugepages));
}

TEST_F(vfio_compact_mock_domain, simple_close)
{
}

TEST_F(vfio_compact_mock_domain, basic)
{
	struct vfio_iommu_type1_dma_unmap unmap_cmd = {
		.argsz = sizeof(unmap_cmd),
	};
	struct vfio_iommu_type1_dma_map map_cmd = {
		.argsz = sizeof(map_cmd),
	};

	__u64 *user_va = &map_cmd.vaddr;
	__u64 *length = &map_cmd.size;
	__u64 *iova = &map_cmd.iova;

	mock_domain_basic(true, &map_cmd, user_va, iova, length);
}

TEST_F(vfio_compact_mock_domain, all_aligns)
{
	struct vfio_iommu_type1_dma_unmap unmap_cmd = {
		.argsz = sizeof(unmap_cmd),
	};
	struct vfio_iommu_type1_dma_map map_cmd = {
		.argsz = sizeof(map_cmd),
	};

	__u64 *unmap_length = &unmap_cmd.size;
	__u64 *unmap_iova = &unmap_cmd.iova;
	__u64 *map_length = &map_cmd.size;
	__u64 *map_iova = &map_cmd.iova;
	__u64 *user_va = &map_cmd.vaddr;

	mock_domain_all_aligns(true, map_cmd, unmap_cmd, user_va,
			       map_iova, map_length, unmap_iova, unmap_length);
};

TEST_HARNESS_MAIN
