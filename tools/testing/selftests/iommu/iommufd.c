// SPDX-License-Identifier: GPL-2.0-only
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>

#include "../kselftest_harness.h"

#define __EXPORTED_HEADERS__
#include <linux/iommufd.h>

#define ALIGN_DOWN(x, align_to) ((x) & ~((align_to)-1))

static uint64_t buffer[64*1024] __attribute__((aligned(4096)));

static unsigned long PAGE_SIZE;
static __attribute__((constructor)) void setup_page_size(void)
{
	PAGE_SIZE = sysconf(_SC_PAGE_SIZE);
}

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
};

FIXTURE_SETUP(iommufd_ioas) {
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	ASSERT_NE(0, alloc_cmd.out_ioas_id);
	self->ioas_id = alloc_cmd.out_ioas_id;
}

FIXTURE_TEARDOWN(iommufd_ioas) {
	ASSERT_EQ(0, close(self->fd));
}

TEST_F(iommufd_ioas, ioas_auto_destroy)
{
}

TEST_F(iommufd_ioas, ioas_destroy)
{
	struct iommu_destroy destroy_cmd = {
		.size = sizeof(destroy_cmd),
		.id = self->ioas_id,
	};

	/* Can allocate and manually free an IOAS table */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
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
		.user_va = ALIGN_DOWN((uintptr_t)buffer, PAGE_SIZE),
		.length = PAGE_SIZE,
	};

	/* Can allocate and manually free an IOAS table with an area */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
}

TEST_F(iommufd_ioas, ioas_area_auto_destroy)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.ioas_id = self->ioas_id,
		.user_va = ALIGN_DOWN((uintptr_t)buffer, PAGE_SIZE),
		.length = PAGE_SIZE,
	};
	int i;

	/* Can allocate and automatically free an IOAS table with many areas */
	for (i = 0; i != 10; i++) {
		map_cmd.iova = i * PAGE_SIZE;
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
		.user_va = ALIGN_DOWN((uintptr_t)buffer, PAGE_SIZE),
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
	};
	int i;

	/* Unmap fails */
	for (i = 0; i != 10; i++) {
		unmap_cmd.iova = i * PAGE_SIZE;
		EXPECT_ERRNO(ENOENT, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
					   &unmap_cmd));
	}

	/* Unmap works */
	for (i = 0; i != 10; i++) {
		map_cmd.iova = i * PAGE_SIZE;
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	}
	for (i = 0; i != 10; i++) {
		unmap_cmd.iova = i * PAGE_SIZE;
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
				   &unmap_cmd));
	}

	/* Split fails */
	map_cmd.length = PAGE_SIZE * 2;
	map_cmd.iova = 16 * PAGE_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	unmap_cmd.iova = 16 * PAGE_SIZE;
	EXPECT_ERRNO(ENOENT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap_cmd));
	unmap_cmd.iova = 17 * PAGE_SIZE;
	EXPECT_ERRNO(ENOENT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap_cmd));

	/* Over map fails */
	map_cmd.length = PAGE_SIZE * 2;
	map_cmd.iova = 16 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE;
	map_cmd.iova = 16 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE;
	map_cmd.iova = 17 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE * 2;
	map_cmd.iova = 15 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE * 3;
	map_cmd.iova = 15 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));

	/* unmap all works */
	unmap_cmd.iova = 0;
	unmap_cmd.length = UINT64_MAX;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap_cmd));
}

TEST_F(iommufd_ioas, area_auto_iova)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
		.user_va = ALIGN_DOWN((uintptr_t)buffer, PAGE_SIZE),
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
}

TEST_F(iommufd_ioas, copy_area)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.length = PAGE_SIZE,
		.user_va = ALIGN_DOWN((uintptr_t)buffer, PAGE_SIZE),
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

	map_cmd.iova = 0;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));

	/* Copy inside a single IOAS */
	copy_cmd.src_iova = 0;
	copy_cmd.dst_iova = PAGE_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_COPY, &copy_cmd));

	/* Copy between IOAS's */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	ASSERT_NE(0, alloc_cmd.out_ioas_id);
	copy_cmd.src_iova = 0;
	copy_cmd.dst_iova = 0;
	copy_cmd.dst_ioas_id = alloc_cmd.out_ioas_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_COPY, &copy_cmd));
}

TEST_F(iommufd_ioas, iova_ranges)
{
	struct iommu_ioas_pagetable_iova_ranges *cmd = (void *)buffer;

	*cmd = (struct iommu_ioas_pagetable_iova_ranges){
		.size = sizeof(buffer),
		.ioas_id = self->ioas_id,
	};

	/* Range can be read */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, cmd));
	EXPECT_EQ(1, cmd->out_num_iovas);
	EXPECT_EQ(0, cmd->out_valid_iovas[0].start);
	EXPECT_EQ(SIZE_MAX - PAGE_SIZE, cmd->out_valid_iovas[0].last);

	/* Buffer too small */
	cmd->size = sizeof(*cmd);
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, cmd));
	EXPECT_EQ(1, cmd->out_num_iovas);
}

TEST_HARNESS_MAIN
