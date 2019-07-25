/*
 * cgroup_workingset.c - control group workingset subsystem
 *
 * Copyright Huawei Corparation, 2017
 * Author: Wanglai.Yao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/module.h>
#include <linux/cgroup.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/rbtree_augmented.h>
#include <linux/cpu.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/mm_inline.h>
#include <linux/kthread.h>
#include <crypto/hash.h>
#include <linux/time.h>
#include <linux/swap.h>
#include <linux/rmap.h>
#include <linux/blkdev.h>
#include <linux/version.h>

#define CGROUP_WORKINGSET_VERSION	(10)

#define FILE_PAGESEQ_BITS				16
#define PAGE_MAJOR_BITS				1
#define PAGE_RANGE_HEAD_BITS			1
#define FILE_SEQNUM_BITS				10
#define FILE_OFFSET_BITS				(8 * sizeof(uint32_t) - FILE_SEQNUM_BITS \
										- PAGE_RANGE_HEAD_BITS - PAGE_MAJOR_BITS)
#define PAGE_TOUCHED_CNT_SHIFT		(FILE_SEQNUM_BITS + FILE_OFFSET_BITS + PAGE_RANGE_HEAD_BITS + PAGE_MAJOR_BITS)
#define PAGE_MAJOR_SHIFT				(FILE_SEQNUM_BITS + FILE_OFFSET_BITS + PAGE_RANGE_HEAD_BITS)
#define PAGE_MAJOR_MASK				((1U << PAGE_MAJOR_BITS) - 1)
#define PAGE_RANGE_HEAD_SHIFT			(FILE_SEQNUM_BITS + FILE_OFFSET_BITS)
#define PAGE_RANGE_HEAD_MASK			((1U << PAGE_RANGE_HEAD_BITS) - 1)
#define FILE_IDX_AND_OFFSET_MASK		((1U << (FILE_SEQNUM_BITS + FILE_OFFSET_BITS)) - 1)
#define MAX_TOUCHED_FILES_COUNT		((1U << FILE_SEQNUM_BITS) - 1)
#define MAX_TOUCHED_FILE_OFFSET		((1U << FILE_OFFSET_BITS) - 1)
#define MAX_TOUCHED_PAGES_COUNT		((1ULL << FILE_PAGESEQ_BITS) - 1)

#define FILPS_PER_PAGE					(PAGE_SIZE / sizeof(struct page*))
#define FILP_PAGES_COUNT				((MAX_TOUCHED_FILES_COUNT + FILPS_PER_PAGE - 1) / FILPS_PER_PAGE)

#define COLLECTOR_CACHE_SIZE_ORDER			(4)
#define COLLECTOR_CACHE_SIZE					(PAGE_SIZE << COLLECTOR_CACHE_SIZE_ORDER)
#define COLLECTOR_ONCE_DEALWITH_COUNT		(64)
#define COLLECTOR_REMAIN_CACHE_LOW_WATER	(COLLECTOR_ONCE_DEALWITH_COUNT << 4)

#define PAGECACHEINFO_PER_PAGE			(PAGE_SIZE / sizeof(struct s_pagecache_info))
#define PAGECACHE_INVALID_OFFSET			(~0U)

#define WORKINGSET_RECORD_MAGIC			(0x2b3c5d8e)
#define MAX_WORKINGSET_RECORDS			(40)
#define PATH_MAX_CHAR						256
#define MAX_CRCOMP_STRM_COUNT			2

#define CARE_BLKIO_MIN_THRESHOLD					20
#define BLKIO_PERCENTAGE_THRESHOLD_FOR_UPDATE	2
#define CACHE_MISSED_PERCENTAGE_THRESHOLD_FOR_BLKIO	80

#define CREATE_HANDLE(file_num, file_offset)	\
({	\
	unsigned int handle;	\
	\
	handle = file_num;	\
	handle <<= FILE_OFFSET_BITS;	\
	handle |= file_offset & MAX_TOUCHED_FILE_OFFSET;	\
	handle;	\
})

/* the commands what sends to workingset*/
enum workingset_monitor_states {
	E_MONITOR_STATE_OUTOFWORK,
	E_MONITOR_STATE_INWORKING,
	E_MONITOR_STATE_PAUSED,
	E_MONITOR_STATE_STOP,
	E_MONITOR_STATE_ABORT,
	E_MONITOR_STATE_PREREAD,
	E_MONITOR_STATE_BACKUP,
	E_MONITOR_STATE_MAX
};


/* the states of workingset*/
enum cgroup_workingset_states {
	E_CGROUP_STATE_OFFLINE = 0,
	E_CGROUP_STATE_ONLINE = (1 << 7),
	E_CGROUP_STATE_MONITOR_BITMASK	= (E_CGROUP_STATE_ONLINE - 1),
	E_CGROUP_STATE_MONITORING = (1 << 6),
	E_CGROUP_STATE_MONITOR_OUTOFWORK = (E_CGROUP_STATE_ONLINE | E_MONITOR_STATE_OUTOFWORK),
	E_CGROUP_STATE_MONITOR_INWORKING = (E_CGROUP_STATE_ONLINE | E_CGROUP_STATE_MONITORING | E_MONITOR_STATE_INWORKING),
	E_CGROUP_STATE_MONITOR_PAUSED = (E_CGROUP_STATE_ONLINE | E_MONITOR_STATE_PAUSED),
	E_CGROUP_STATE_MONITOR_STOP = (E_CGROUP_STATE_ONLINE | E_MONITOR_STATE_STOP),
	E_CGROUP_STATE_MONITOR_ABORT = (E_CGROUP_STATE_ONLINE | E_MONITOR_STATE_ABORT),
	E_CGROUP_STATE_MONITOR_PREREAD = (E_CGROUP_STATE_ONLINE | E_MONITOR_STATE_PREREAD),
	E_CGROUP_STATE_MONITOR_BACKUP = (E_CGROUP_STATE_ONLINE | E_MONITOR_STATE_BACKUP),
	E_CGROUP_STATE_MAX,
};

/* the events what collector waiting for*/
enum workingset_wait_flags {
	F_NONE,
	F_COLLECT_PENDING,
	F_RECORD_PENDING,
};

/* the states or flags of records*/
enum workingset_record_state {
	E_RECORD_STATE_UNUSED = 0x00,
	E_RECORD_STATE_USED = 0x01,
	E_RECORD_STATE_DIRTY = 0x02,	/* the flag indicate writeback the record*/
	E_RECORD_STATE_COLLECTING = 0x04,
	E_RECORD_STATE_PREREADING = 0x08,
	E_RECORD_STATE_PAUSE = 0x10,
	E_RECORD_STATE_DATA_FROM_BACKUP = 0x20,	/* the flag indicate the playload buffer is contiguous*/
	E_RECORD_STATE_UPDATE_BASE_BLKIO = 0x40,	/* the flag indicate the blkio count that first time on prereading*/
	E_RECORD_STATE_UPDATE_HEADER_ONLY = 0x80,	/* the flag indicate write only record header to disk*/
};

struct s_path_node {
	/*the hash code of this path*/
	unsigned hashcode;
	unsigned pathlen;
	char *path;
};

struct s_range {
	unsigned start;
	unsigned end;
};

struct s_filp_list {
	struct file *filp;
	struct s_filp_list *next;
};

struct s_file_info {
	/*list to the workingset file list*/
	struct list_head list;
	/*the list of pointer of struct file*/
	struct s_filp_list *filp_list;
	/*the path info of file*/
	struct s_path_node path_node;
	/**
	* the count of page sequences belong to this file,
	* the range including single page occupy one pageseq,
	* the range including multi pages occupy two pageseqs.
	**/
	unsigned int pageseq_count;
	/*the root of page cache tree*/
	struct rb_root rbroot;
};

struct s_pagecache_info {
	struct rb_node rbnode;
	/*the offset range of file*/
	struct s_range offset_range;
};

struct s_workingset_owner {
	unsigned uid;
	/*the pid of leader thread*/
	int pid;
	char *name;
	/*the path of record file*/
	char *record_path;
};

struct s_workingset_data {
	unsigned file_cnt;
	/**
	* the count of page sequences belong to this owner,
	* the range including single page occupy one pageseq,
	* the range including multi pages occupy two pageseqs.
	**/
	unsigned pageseq_cnt;
	/*sum of file pages this owner accessed*/
	unsigned page_sum;
	/*the size of pages array*/
	unsigned array_page_cnt;
	/*the pages array that caching the path informations and file offset range informations*/
	struct page **page_array;
	/*the file array*/
	struct s_path_node *file_array;
	/*the file cache array*/
	unsigned *cacheseq;
};

struct s_workingset_record {
	/*list to the global workingset record list*/
	struct list_head list;
	struct s_workingset_owner owner;
	struct s_workingset_data data;
	struct mutex mutex;
	/*the state of a record*/
	unsigned state;
#ifdef CONFIG_TASK_DELAY_ACCT
	/*the blkio count of main thread when first time on prereading*/
	unsigned short leader_blkio_cnt;
	/*tell us if or not need collect again*/
	unsigned short need_update;
#endif
	/*the pointer of struct files array*/
	struct file **preread_filpp;
	/*pages for caching struct files that be opened on prereading */
	struct page *filp_pages[FILP_PAGES_COUNT];
};

struct s_workingset_backup_record_header {
	unsigned magic;
	unsigned header_crc;
	/*version of the record file, it must be equal version of this module.*/
	unsigned record_version;
	/*the count of the file*/
	unsigned file_cnt;
	/**
	* the count of page sequences belong to this owner,
	* the range including single page occupy one pageseq,
	* the range including multi pages occupy two pageseqs.
	**/
	unsigned pageseq_cnt;
	/*sum of accessed file pages*/
	unsigned page_sum;
	/*the size of the playload data*/
	unsigned playload_length;
	/*the checksum of the playload data*/
	unsigned playload_checksum;
#ifdef CONFIG_TASK_DELAY_ACCT
	/*the blkio count of main thread when first time on prereading*/
	unsigned short leader_blkio_cnt;
	/*tell us if or not need collect again*/
	unsigned short need_update;
#else
	unsigned padding1;
	unsigned padding2;
#endif
};

struct s_workingset {
	struct cgroup_subsys_state css;
	struct mutex mutex;
	/*the owner which workingset is working for*/
	struct s_workingset_owner owner;
	unsigned long repeated_count;
	unsigned int page_sum;
	/*the state of workingset*/
	unsigned int state;
#ifdef CONFIG_TASK_DELAY_ACCT
	/*the blkio count of main thread*/
	unsigned short leader_blkio_cnt;
	__u64 leader_blkio_base;
#endif
	unsigned int file_count;
	unsigned int pageseq_count;
	/*the alloc index of pagecache array*/
	unsigned int pagecache_alloc_index;
	bool shrinker_enabled;
	struct shrinker shrinker;
	struct list_head file_list;
	/*pages for caching page offset range information*/
	struct s_pagecache_info *pagecache_array_addr[0];
};

struct s_cachepage_info {
	struct file *filp;
	unsigned	start_offset;
	/*the count of contiguous pagecache*/
	unsigned count:16;
	unsigned pid:16;
};

struct s_workingset_collector {
	spinlock_t lock;
	struct task_struct *collector_thread;
	wait_queue_head_t collect_wait;
	enum workingset_wait_flags wait_flag;
	/*the workingset that collector working for*/
	struct s_workingset *monitor;
	unsigned long discard_count;
	/*the read position of circle buffer*/
	unsigned read_pos;
	/*the write position of circle buffer*/
	unsigned write_pos;
	/*the address of circle buffer*/
	void *circle_buffer;
};

struct s_readpages_control {
	struct file *filp;
	struct address_space *mapping;
	/*the file offset that will be read */
	pgoff_t offset;
	/*the count that file pages was readed*/
	unsigned long nr_to_read;
	/*the count that lru pages was moved*/
	unsigned nr_adjusted;
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
	/*the last page that read from block device */
	struct page *lastpage;
#endif
};

static spinlock_t g_workingset_list_lock;
static LIST_HEAD(g_workingset_list);
static unsigned g_workingset_cnt = 0;
static atomic_t g_preread_abort = ATOMIC_INIT(0);  //use to interrupt prereading process.
static struct s_workingset_collector *workingset_collector = NULL;
static struct crypto_shash *g_tfm;
static const char *moniter_states[E_MONITOR_STATE_MAX] = {"OUTOFWORK", "INWORKING", "PAUSED", "STOP", "ABORT", "PREREAD", "BACKUP"};

/*dynamic debug informatioins controller*/
static bool workingset_debug_enable = 0;
module_param_named(debug_enable, workingset_debug_enable, bool, S_IRUSR | S_IWUSR);
#define workingset_debug(x...) \
	do { \
		if (workingset_debug_enable) \
			pr_info(x); \
	} while (0)

static void workingset_prereader_do_work_locked(struct s_workingset_record *to_preread);
static void workingset_stop_preread_record_locked(struct s_workingset_record *to_preread);

/**
 * workingset_pagecache_info_cache_alloc - alloc a pagecache space from the pagecache array of workingset
 * @workingset: the owner of pagecache array
 *
 * Return the pointer of a free pagecache space or null.
 */
static struct s_pagecache_info *workingset_pagecache_info_cache_alloc(struct s_workingset *workingset)
{
	unsigned page_idx = workingset->pagecache_alloc_index / PAGECACHEINFO_PER_PAGE;
	unsigned off_in_page = workingset->pagecache_alloc_index % PAGECACHEINFO_PER_PAGE;

	/* the size of struct s_workingset space is PAGE_SIZE, including essentials and pages array*/
	if (offsetof(struct s_workingset, pagecache_array_addr) + (page_idx + 1) * sizeof(struct s_pagecache_info **) > PAGE_SIZE)
		goto out;

	if (!workingset->pagecache_array_addr[page_idx]) {
		workingset->pagecache_array_addr[page_idx] = (struct s_pagecache_info *)get_zeroed_page(GFP_KERNEL | __GFP_HIGHMEM);
		if (!workingset->pagecache_array_addr[page_idx]) {
			goto out;
		}
	}

	return workingset->pagecache_array_addr[page_idx] + off_in_page;

out:
	return NULL;
}

/*********************************
* shrinker of workingset code
* permmit shrinking the pagecache array memory of workingset only if
* the workingset is outofwork or aborted.
**********************************/
static unsigned long workingset_shrinker_scan(struct shrinker *shrinker,
		struct shrink_control *sc)
{
	int idx, stop_idx, max_count;
	unsigned long pages_freed;
	struct s_workingset *workingset = container_of(shrinker, struct s_workingset,
			shrinker);

	max_count = (PAGE_SIZE - offsetof(struct s_workingset, pagecache_array_addr)) / sizeof(struct s_pagecache_info **);
	if (!mutex_trylock(&workingset->mutex))
		return SHRINK_STOP;

	/* reclaim the page array when the workingset is out of work*/
	if ((E_CGROUP_STATE_MONITOR_OUTOFWORK == workingset->state)
		|| (E_CGROUP_STATE_MONITOR_ABORT == workingset->state)) {
		if (!workingset->pagecache_alloc_index)
			stop_idx = -1;
		else
			stop_idx = workingset->pagecache_alloc_index / PAGECACHEINFO_PER_PAGE;

		pages_freed = 0;
		for (idx = max_count - 1; idx > stop_idx; idx--) {
			if (workingset->pagecache_array_addr[idx]) {
				free_page((unsigned long)workingset->pagecache_array_addr[idx]);
				workingset->pagecache_array_addr[idx] = NULL;
				pages_freed++;
			}
		}
	} else {
		pages_freed = 0;
	}

	mutex_unlock(&workingset->mutex);
	workingset_debug("%s: reclaimed %lu pages\n", __func__, pages_freed);

	return pages_freed ? pages_freed : SHRINK_STOP;
}

static unsigned long workingset_shrinker_count(struct shrinker *shrinker,
		struct shrink_control *sc)
{
	unsigned idx, max_count;
	unsigned long pages_to_free = 0;
	struct s_workingset *workingset = container_of(shrinker, struct s_workingset,
			shrinker);

	max_count = (PAGE_SIZE - offsetof(struct s_workingset, pagecache_array_addr)) / sizeof(struct s_pagecache_info **);
	if (!mutex_trylock(&workingset->mutex))
		return 0;

	/* reclaim the page array when the workingset is out of work*/
	if ((E_CGROUP_STATE_MONITOR_OUTOFWORK == workingset->state)
		|| (E_CGROUP_STATE_MONITOR_ABORT == workingset->state)) {
		for (idx = 0; idx < max_count; idx++) {
			if (workingset->pagecache_array_addr[idx])
				pages_to_free++;
			else
				break;
		}
		if (pages_to_free > 1 + workingset->pagecache_alloc_index / PAGECACHEINFO_PER_PAGE)
			pages_to_free -= 1 + workingset->pagecache_alloc_index / PAGECACHEINFO_PER_PAGE;
		else
			pages_to_free = 0;
	} else {
		pages_to_free = 0;
	}
	mutex_unlock(&workingset->mutex);

	return pages_to_free;
}

static void workingset_unregister_shrinker(struct s_workingset *workingset)
{
	if (workingset->shrinker_enabled) {
		unregister_shrinker(&workingset->shrinker);
		workingset->shrinker_enabled = false;
	}
}

static int workingset_register_shrinker(struct s_workingset *workingset)
{
	workingset->shrinker.scan_objects = workingset_shrinker_scan;
	workingset->shrinker.count_objects = workingset_shrinker_count;
	workingset->shrinker.batch = 0;
	workingset->shrinker.seeks = DEFAULT_SEEKS;

	return register_shrinker(&workingset->shrinker);
}

/*********************************
* crc32 code
**********************************/
static unsigned workingset_crc32c(unsigned crc, const void *address, unsigned int length)
{
	SHASH_DESC_ON_STACK(shash, g_tfm);
	unsigned *ctx = (u32 *)shash_desc_ctx(shash);
	unsigned retval;
	int err;

	shash->tfm = g_tfm;
	shash->flags = 0;
	*ctx = crc;

	err = crypto_shash_update(shash, address, length);
	if (err) {
		pr_err("%s, %d, err=%d\n", __func__, __LINE__, err);
	}
	retval = *ctx;
	barrier_data(ctx);

	return retval;
}

/*********************************
* rbtree code
**********************************/
static struct rb_node *rb_deepest_left_node(const struct rb_node *node)
{
	for (;;) {
		if (node->rb_left)
			node = node->rb_left;
		else
			return (struct rb_node *)node;
	}
}

static struct rb_node *rb_deepest_right_node(const struct rb_node *node)
{
	for (;;) {
		if (node->rb_right)
			node = node->rb_right;
		else
			return (struct rb_node *)node;
	}
}

static struct rb_node *rb_latest_left_ancestor(const struct rb_node *node)
{
	struct rb_node *parent;
	struct rb_node *temp_node = node;

	while (temp_node) {
		parent = rb_parent(temp_node);
		if (parent && temp_node == parent->rb_left)
			temp_node = parent;
		else
			return (struct rb_node *)parent;
	}

	return NULL;
}

static struct rb_node *rb_latest_right_ancestor(const struct rb_node *node)
{
	struct rb_node *parent;
	struct rb_node *temp_node = node;

	while (temp_node) {
		parent = rb_parent(temp_node);
		if (parent && temp_node == parent->rb_right)
			temp_node = parent;
		else
			return (struct rb_node *)parent;
	}

	return NULL;
}

struct rb_node *rb_prev_middleorder(const struct rb_node *node)
{
	if (!node)
		return NULL;

	if (node->rb_left) {
		return rb_deepest_right_node(node->rb_left);
	} else
		return rb_latest_left_ancestor(node);
}

struct rb_node *rb_next_middleorder(const struct rb_node *node)
{
	if (!node)
		return NULL;

	if (node->rb_right) {
		return rb_deepest_left_node(node->rb_right);
	} else
		return rb_latest_right_ancestor(node);
}

struct rb_node *rb_first_middleorder(const struct rb_root *root)
{
	if (!root->rb_node)
		return NULL;

	return rb_deepest_left_node(root->rb_node);
}

#define rbtree_middleorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_middleorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_middleorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)

#define rbtree_middleorder_for_each_entry_safe_continue(pos, n, root, field) \
	for (; pos && ({ n = rb_entry_safe(rb_next_middleorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)

static void workingset_range_rb_erase(struct rb_root *root, struct s_pagecache_info *entry)
{
	if (!RB_EMPTY_NODE(&entry->rbnode)) {
		rb_erase(&entry->rbnode, root);
		RB_CLEAR_NODE(&entry->rbnode);
	}
}

static inline void workingset_range_rb_change_to_front(struct s_pagecache_info **oldEntry, struct s_pagecache_info **newEntry)
{
	struct s_pagecache_info *temp;

	if (*oldEntry < *newEntry) {
		temp = *oldEntry;
		*oldEntry = *newEntry;
		*newEntry = temp;
	}
}

/**
 * workingset_range_rb_insert - insert a page offset range into pageoffset range tree of a file.
 * @root: the root of page range tree
 * @entry: a entry of page offset range.
 * @major_touched: if or not the page is touched by main thread.
 * @repeat_pages: output the count of overlaped page offset.
 * @page_count_delta: output the count of added page offset range.
 *
 * In the case that a entry with the same offset is found, the function returns overlapped range or adjoined range.
 */
static struct s_pagecache_info* workingset_range_rb_insert(struct rb_root *root, struct s_pagecache_info *entry, int major_touched, unsigned *repeat_pages, int *page_count_delta)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct s_pagecache_info *myentry, *merged_entry = NULL;  //the merged range entry
	unsigned cur_range_start, cur_range_end;
	unsigned start = entry->offset_range.start & FILE_IDX_AND_OFFSET_MASK;
	unsigned end = entry->offset_range.end & FILE_IDX_AND_OFFSET_MASK;
	bool probe_left = false, probe_right = false, look_otherside = false;
	struct s_range overrange; //the overlapped range
	unsigned repeat_cnt = 0;
	int page_delta = 0;
	unsigned file_idx = ((entry->offset_range.start) >> FILE_OFFSET_BITS) & MAX_TOUCHED_FILES_COUNT;

	//range[start, end)
	while (*link) {
		parent = *link;
		myentry = rb_entry(parent, struct s_pagecache_info, rbnode);
		cur_range_start = myentry->offset_range.start & FILE_IDX_AND_OFFSET_MASK;
		cur_range_end = myentry->offset_range.end & FILE_IDX_AND_OFFSET_MASK;

		if (cur_range_start > end)
			link = &(*link)->rb_left;
		else if (cur_range_end < start)
			link = &(*link)->rb_right;
		else {	/*in the case, two ranges is overlapped or adjoined*/
			/*indicate major touched page offset range even if a page was touched by main thread*/
			major_touched |= (myentry->offset_range.start >> PAGE_MAJOR_SHIFT) & PAGE_MAJOR_MASK;

			/**
			* We probe left child tree first, and merge overlapped range or adjoined range, then probe right child tree.
			* exchange the position between inserted range with adjoined range in order to preread these file pages
			* as early as possible. and dicard the space of erased pagecache range in pagecache array.
			*/
			if (!merged_entry || probe_left) {
				if (merged_entry)
					look_otherside = true;

				if (start < cur_range_start) {
					/*in the case, inserted entry or merged entry including current offset range*/
					overrange.start = cur_range_start;
					parent = rb_prev_middleorder(&myentry->rbnode);
					if (probe_left) {
						workingset_range_rb_change_to_front(&myentry, &merged_entry);
						workingset_range_rb_erase(root, myentry);
						page_delta -= (myentry->offset_range.start & (PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT))? 2 : 1;
						myentry->offset_range.start = myentry->offset_range.end = PAGECACHE_INVALID_OFFSET;
					}

					/*probe left tree if there are smaller offset ranges*/
					if (!parent)
						probe_left = false;
					else
						probe_left = true;
				} else {
					/*in the case, inserted entry or merged entry overlapped with current offset range*/
					if (probe_left) {
						workingset_range_rb_change_to_front(&myentry, &merged_entry);
						workingset_range_rb_erase(root, myentry);
						page_delta -= (myentry->offset_range.start & (PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT))? 2 : 1;
						myentry->offset_range.start = myentry->offset_range.end = PAGECACHE_INVALID_OFFSET;
					}
					overrange.start = start;
					start = cur_range_start;
					probe_left = false;
				}
				if (merged_entry)
					overrange.end = cur_range_end;
			}

			/*in the case, merge range first time or there are not any small offset range.*/
			if (!merged_entry || (probe_right && !probe_left)) {
				if (look_otherside) {
					/*there are not any small offset range, so we look aside bigger offset range*/
					look_otherside = false;
					parent = rb_next_middleorder(&merged_entry->rbnode);
					if (!parent)
						probe_right = false;
				} else if (end > cur_range_end) {
					/*in the case, inserted entry or merged entry including current offset range*/
					if (!probe_left)
						parent = rb_next_middleorder(&myentry->rbnode);
					if (probe_right) {
						workingset_range_rb_change_to_front(&myentry, &merged_entry);
						workingset_range_rb_erase(root, myentry);
						page_delta -= (myentry->offset_range.start & (PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT))? 2 : 1;
						myentry->offset_range.start = myentry->offset_range.end = PAGECACHE_INVALID_OFFSET;
					}

					if (merged_entry)
						overrange.start = cur_range_start;
					overrange.end = cur_range_end;
					/*stop probing right tree if there are not any bigger offset ranges*/
					if (!parent)
						probe_right = false;
					else
						probe_right = true;
				} else {
					/*in the case, inserted entry or merged entry overlapped with current offset range*/
					if (probe_right) {
						workingset_range_rb_change_to_front(&myentry, &merged_entry);
						workingset_range_rb_erase(root, myentry);
						page_delta -= (myentry->offset_range.start & (PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT))? 2 : 1;
						myentry->offset_range.start = myentry->offset_range.end = PAGECACHE_INVALID_OFFSET;
					}
					if (merged_entry)
						overrange.start = cur_range_start;
					overrange.end = end;

					end = cur_range_end;
					probe_right = false;
				}
			}

			if (!merged_entry) {
				merged_entry = myentry;
			}

			if (overrange.end > overrange.start)
				repeat_cnt += overrange.end - overrange.start;
			else if (overrange.end < overrange.start)
				pr_err("%s: file[%x] overrange[%x, %x] should be never happend!\n",
				__func__, file_idx, overrange.start, overrange.end);

			/*set 1 to the range header bit if the range has multipages, or clear the range header bit*/
			if (end - start > 1) {
				if (!(merged_entry->offset_range.start & (PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT)))
					page_delta += 1;
				merged_entry->offset_range.start = start | (PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT);
				merged_entry->offset_range.end = end | (PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT);
			} else {
				merged_entry->offset_range.start = start & ~(PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT);
				merged_entry->offset_range.end = end & ~(PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT);
			}

			if (major_touched) {
				merged_entry->offset_range.start |= (major_touched & PAGE_MAJOR_MASK) << PAGE_MAJOR_SHIFT;
				merged_entry->offset_range.end |= (major_touched & PAGE_MAJOR_MASK) << PAGE_MAJOR_SHIFT;
			}

			if (!probe_right && !probe_left)
				break;
			link = &parent;
			continue;
		}

		if (merged_entry) {
			/*there are not any small offset range, so we look aside bigger offset range*/
			if (probe_left && probe_right) {
				probe_left = false;
				parent = rb_next_middleorder(&merged_entry->rbnode);
				if (parent) {
					link = &parent;
					continue;
				}
			}
			break;
		}
	}

	if (!merged_entry) {
		/*in the case, the inserted range has not overlapped or adjoined with any ranges*/
		if (major_touched) {
			entry->offset_range.start |= (major_touched & PAGE_MAJOR_MASK) << PAGE_MAJOR_SHIFT;
			entry->offset_range.end |= (major_touched & PAGE_MAJOR_MASK) << PAGE_MAJOR_SHIFT;
		}
		rb_link_node(&entry->rbnode, parent, link);
		rb_insert_color(&entry->rbnode, root);
	} else {
		*repeat_pages = repeat_cnt;
		*page_count_delta = page_delta;
	}

	return merged_entry;
}

/*********************************
* the operation of fs code
**********************************/
static void workingset_recycle_record(struct s_workingset_record *record)
{
	int idx;

	//free file_array only because use one vmalloc for file_array and cacheseq.
	if (record->data.file_array) {
		for (idx = 0; idx < record->data.file_cnt; idx++) {
			if (record->data.file_array[idx].path
				&& !(record->state & E_RECORD_STATE_DATA_FROM_BACKUP)) {
				kfree(record->data.file_array[idx].path);
				record->data.file_array[idx].path = NULL;
			}
		}
	}
	record->data.file_cnt = 0;
	record->data.pageseq_cnt = 0;
	record->data.page_sum = 0;
#ifdef CONFIG_TASK_DELAY_ACCT
	record->leader_blkio_cnt = 0;
	record->need_update = 0;
#endif
	record->state &= E_RECORD_STATE_DATA_FROM_BACKUP;
}

static bool workingset_backup_record(struct s_workingset_record *record)
{
	bool ret = false;
	struct file *filp;
	struct s_workingset_backup_record_header header = {0,};
	unsigned checksum = 0, crc_val;
	unsigned length = 0;
	unsigned pathnode_size;
	unsigned idx;
	loff_t pos = sizeof(header);

	if (!record->data.file_cnt || !record->data.pageseq_cnt || !record->owner.record_path)
		return ret;

	workingset_debug("%s: writeback %s record data to %s\n", __func__, record->owner.name, record->owner.record_path);
	if (record->state & E_RECORD_STATE_UPDATE_HEADER_ONLY) {
		//in the case, we update the header of record only.
		filp = filp_open(record->owner.record_path, O_LARGEFILE | O_RDWR, S_IRUSR | S_IWUSR);
		if (IS_ERR_OR_NULL(filp)) {
			pr_err("%s: writeback %s record data to %s, ret = %ld\n", __func__, record->owner.name, record->owner.record_path, PTR_ERR(filp));
			return ret;
		}

		length = kernel_read(filp, 0, (char*)&header, sizeof(header));
		if (sizeof(header) != length) {
			pr_err("%s line %d: kernel_read failed, len = %d\n", __func__, __LINE__, length);
			goto out;
		}

		if (header.magic != WORKINGSET_RECORD_MAGIC
			|| header.record_version != CGROUP_WORKINGSET_VERSION
			|| header.header_crc != workingset_crc32c(0,
			&header.record_version, sizeof(header) - offsetof(struct s_workingset_backup_record_header, record_version))) {
			pr_err("%s line %d: magic=%u, headercrc=%u\n", __func__, __LINE__, header.magic, header.header_crc);
			goto out;
		}
#ifdef CONFIG_TASK_DELAY_ACCT
		header.leader_blkio_cnt = record->leader_blkio_cnt;
		header.need_update = record->need_update;
#endif
	} else {
		filp = filp_open(record->owner.record_path, O_LARGEFILE | O_WRONLY, S_IRUSR | S_IWUSR);
		if (IS_ERR_OR_NULL(filp)) {
			pr_err("%s: writeback %s record data to %s, ret = %ld\n", __func__, record->owner.name, record->owner.record_path, PTR_ERR(filp));
			return ret;
		}

		pathnode_size = sizeof(struct s_path_node) * record->data.file_cnt;
		crc_val = workingset_crc32c(checksum, record->data.file_array, pathnode_size);
		if (crc_val == checksum) {
			pr_err("%s line %d: checksum=%u crc_val=%u\n", __func__, __LINE__, checksum, crc_val);
			goto out;
		}

		checksum = crc_val;
		if (pathnode_size != kernel_write(filp, (char*)record->data.file_array, pathnode_size, pos)) {
			pr_err("%s line %d: kernel_write failed\n", __func__, __LINE__);
			goto out;
		}

		pos += pathnode_size;
		for (idx = 0; idx < record->data.file_cnt; idx++) {
			if (!record->data.file_array[idx].path)
				continue;

			length = record->data.file_array[idx].pathlen? record->data.file_array[idx].pathlen + 1 : strlen(record->data.file_array[idx].path) + 1;
			crc_val = workingset_crc32c(checksum, record->data.file_array[idx].path, length);
			if (crc_val == checksum) {
				pr_err("%s line %d: checksum=%u crc_val=%u\n", __func__, __LINE__, checksum, crc_val);
				goto out;
			}

			checksum = crc_val;
			if (length != kernel_write(filp, record->data.file_array[idx].path, length, pos)) {
				pr_err("%s line %d: kernel_write failed\n", __func__, __LINE__);
				goto out;
			}
			pos += length;
		}

		length = sizeof(unsigned) * record->data.pageseq_cnt;
		crc_val = workingset_crc32c(checksum, record->data.cacheseq, length);
		if (crc_val == checksum) {
			pr_err("%s line %d: checksum=%u crc_val=%u\n", __func__, __LINE__, checksum, crc_val);
			goto out;
		}

		checksum = crc_val;
		if (length != kernel_write(filp, (char*)record->data.cacheseq, length, pos)) {
			pr_err("%s line %d: kernel_write failed\n", __func__, __LINE__);
			goto out;
		}

		pos += length;
		//truncate invalid data if it is existed.
		if (vfs_truncate(&filp->f_path, pos))
			pr_warn("%s %s vfs_truncate failed!", __func__, record->owner.record_path);

		header.file_cnt = record->data.file_cnt;
		header.pageseq_cnt = record->data.pageseq_cnt;
		header.page_sum = record->data.page_sum;
		header.playload_checksum = checksum;
		header.playload_length = pos - sizeof(header);
		header.record_version = CGROUP_WORKINGSET_VERSION;
#ifdef CONFIG_TASK_DELAY_ACCT
		header.leader_blkio_cnt = record->leader_blkio_cnt;
		header.need_update = record->need_update;
#endif
	}

	crc_val = workingset_crc32c(0,
		&header.record_version, sizeof(header) - offsetof(struct s_workingset_backup_record_header, record_version));
	if (!crc_val) {
		pr_err("%s line %d: checksum=0 crc_val=%u\n", __func__, __LINE__, crc_val);
		goto out;
	}

	header.header_crc = crc_val;
	header.magic = WORKINGSET_RECORD_MAGIC;
	if (sizeof(header) == kernel_write(filp, (char*)&header, sizeof(header), 0))
		ret = true;
	else {
		pr_err("%s line %d: kernel_write failed\n", __func__, __LINE__);
		goto out;
	}
out:
	filp_close(filp, NULL);
	return ret;
}

static void workingset_free_record_exclude_filespath(struct s_workingset_record *record)
{
	int idx;

	if (record->owner.name) {
		kfree(record->owner.name);
		record->owner.name = NULL;
	}
	if (record->owner.record_path) {
		kfree(record->owner.record_path);
		record->owner.record_path = NULL;
	}

	if (record->data.page_array) {
		vunmap(record->data.file_array);
		for (idx = 0; idx < record->data.array_page_cnt; idx++) {
			__free_page(record->data.page_array[idx]);
		}
		kfree(record->data.page_array);
		record->data.page_array = NULL;
	}
	record->data.array_page_cnt = 0;
	record->data.file_array = NULL;
	record->data.cacheseq = NULL;
	record->data.file_cnt = 0;
	record->owner.uid = 0;
	record->state = E_RECORD_STATE_UNUSED;
}

/**
 * workingset_record_realloc_ownerbuffer_if_need - realloc memory for information of new owner .
 * @scanned: the old owner be replaced.
 * @owner: the new owner.
 *
 * if the size of @scanned owner information is larger than @owner requests, reuse the memory of @scanned.
 */
static int workingset_record_realloc_ownerbuffer_if_need(struct s_workingset_owner *scanned, struct s_workingset_owner *owner)
{
	int ret = 0;
	unsigned name_len, path_len;
	char *new_name = NULL;
	char* new_path = NULL;

	if (!owner->name || !owner->record_path)
		return -EINVAL;

	name_len = strlen(owner->name);
	path_len = strlen(owner->record_path);
	if (!scanned->name || (strlen(scanned->name) < name_len)) {
		new_name = kzalloc(name_len + 1, GFP_KERNEL);
		if (!new_name) {
			ret = -ENOMEM;
			goto alloc_name_fail;
		}
	}
	if (!scanned->record_path || (strlen(scanned->record_path) < path_len)) {
		new_path = kzalloc(path_len + 1, GFP_KERNEL);
		if (!new_path) {
			ret = -ENOMEM;
			goto alloc_path_fail;
		}
	}

	if (new_name) {
		if (scanned->name)
			kfree(scanned->name);
		scanned->name = new_name;
	}
	if (new_path) {
		if (scanned->record_path)
			kfree(scanned->record_path);
		scanned->record_path = new_path;
	}
	return 0;

alloc_path_fail:
	if (new_name)
		kfree(new_name);
alloc_name_fail:
	return ret;
}

static void workingset_writeback_last_record_if_need(void)
{
	struct s_workingset_record *record;

	if (g_workingset_cnt >= MAX_WORKINGSET_RECORDS) {
		record = list_empty(&g_workingset_list)? NULL : list_last_entry(&g_workingset_list, struct s_workingset_record, list);
		if (record) {
			mutex_lock(&record->mutex);
			if ((record->state & (E_RECORD_STATE_USED | E_RECORD_STATE_DIRTY))
				== (E_RECORD_STATE_USED | E_RECORD_STATE_DIRTY)) {
				workingset_backup_record(record);
				record->state &= ~(E_RECORD_STATE_DIRTY | E_RECORD_STATE_UPDATE_HEADER_ONLY);
			}
			mutex_unlock(&record->mutex);
		}
	}
}

static void workingset_writeback_all_records(void)
{
	LIST_HEAD(temp_list);
	struct s_workingset_record *record;
	struct list_head *pos;
	struct list_head *head = &g_workingset_list;
	int total_records = 0;
	int writeback_cnt = 0;

	spin_lock(&g_workingset_list_lock);
	while (!list_empty(head)) {
		pos = head->prev;
		list_del(pos);
		g_workingset_cnt--;
		spin_unlock(&g_workingset_list_lock);
		record = container_of(pos, struct s_workingset_record, list);
		mutex_lock(&record->mutex);
		if ((record->state & (E_RECORD_STATE_USED | E_RECORD_STATE_DIRTY))
			== (E_RECORD_STATE_USED | E_RECORD_STATE_DIRTY)) {
			if (workingset_backup_record(record))
				writeback_cnt++;
			record->state &= ~(E_RECORD_STATE_DIRTY | E_RECORD_STATE_UPDATE_HEADER_ONLY);
		}
		total_records++;
		list_add(pos, &temp_list);
		mutex_unlock(&record->mutex);
		spin_lock(&g_workingset_list_lock);
	}
	list_splice(&temp_list, &g_workingset_list);
	g_workingset_cnt += total_records;
	spin_unlock(&g_workingset_list_lock);
	workingset_debug("%s: total records=%u, writebacked=%d\n", __func__, total_records, writeback_cnt);
}

static struct s_workingset_record* workingset_get_record_from_backup(struct s_workingset_owner *owner)
{
	struct list_head *pos;
	struct list_head *head = &g_workingset_list;
	struct page *page;
	struct page **page_array = NULL;
	struct file *filp;
	struct s_workingset_record* record = NULL;
	struct s_workingset_backup_record_header header;
	unsigned idx = 0;
	unsigned playload_pages;
	unsigned pathnode_size;
	unsigned len = 0;
	void* playload;
	bool is_replace = false;
	int ret;

	filp = filp_open(owner->record_path, O_LARGEFILE | O_RDONLY, 0);
	if (IS_ERR_OR_NULL(filp))
		return NULL;

	workingset_debug("%s: read record data from %s\n", __func__, owner->record_path);
	ret = kernel_read(filp, 0, (char*)&header, sizeof(header));
	if (sizeof(header) != ret) {
		if (ret)
			pr_err("%s line %d: kernel_read failed, ret = %d\n", __func__, __LINE__, ret);
		goto out;
	}

	if (header.magic != WORKINGSET_RECORD_MAGIC
		|| header.record_version != CGROUP_WORKINGSET_VERSION
		|| header.header_crc != workingset_crc32c(0,
		&header.record_version, sizeof(header) - offsetof(struct s_workingset_backup_record_header, record_version))) {
		pr_err("%s line %d: magic=%u, headercrc=%u, version of record=%u\n", __func__, __LINE__, header.magic, header.header_crc, header.record_version);
		goto out;
	}

	if (header.playload_length > (MAX_TOUCHED_PAGES_COUNT * sizeof(unsigned)) +
	    (sizeof(struct s_path_node) + PATH_MAX_CHAR) * MAX_TOUCHED_FILES_COUNT) {
		pr_err("%s line %d: the data of record maybe falsified! playload(length = %u) is too large than max pagecache(%u)\n", __func__, __LINE__, header.playload_length, (MAX_TOUCHED_PAGES_COUNT * sizeof(unsigned)));
		goto out;
	}

	playload_pages = DIV_ROUND_UP(header.playload_length, PAGE_SIZE);
	/*replace the oldest clean record in list when there is cached records too many*/
	spin_lock(&g_workingset_list_lock);
	if (g_workingset_cnt >= MAX_WORKINGSET_RECORDS) {
		list_for_each_prev(pos, head) {
			record = container_of(pos, struct s_workingset_record, list);
			if (!(record->state & (E_RECORD_STATE_DIRTY | E_RECORD_STATE_PREREADING))) {
				list_del(&record->list);
				g_workingset_cnt--;
				is_replace = true;
				break;
			}
		}
	}
	spin_unlock(&g_workingset_list_lock);

	if (!is_replace) {
		record = (struct s_workingset_record *)kzalloc(sizeof(struct s_workingset_record), GFP_KERNEL);
		if (!record) {
			pr_err("%s line %d: outofmemory\n", __func__, __LINE__);
			goto out;
		}
		mutex_init(&record->mutex);
	}
	mutex_lock(&record->mutex);

	/**
	* In order to avoid more direct reclaim, so we reuse the memory of old record as far as possible when replace it.
	*/
	if (record->data.array_page_cnt < playload_pages) {
		page_array = (struct page **)kzalloc(sizeof(struct page*) * playload_pages, GFP_KERNEL);
		if (!page_array) {
			pr_err("%s: out of memory, kzalloc %lu bytes failed!\n", __func__, sizeof(struct page*) * playload_pages);
			goto alloc_array_fail;
		}

		if (record->data.array_page_cnt)
			memcpy(page_array, record->data.page_array, sizeof(struct page*) * record->data.array_page_cnt);

		idx = record->data.array_page_cnt;
		while (idx < playload_pages) {
			page = alloc_page(GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO);
			if (!page) {
				pr_err("%s: out of memory, alloc %u pages failed!\n", __func__, playload_pages);
				goto vmap_fail;
			}
			page_array[idx] = page;
			idx++;
		}

		playload = vmap(page_array, playload_pages, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
		if (!playload) {
			pr_err("%s: out of space, vmap %u pages failed!\n", __func__, playload_pages);
			goto vmap_fail;
		}

		if (workingset_record_realloc_ownerbuffer_if_need(&record->owner, owner)) {
			pr_err("%s line %d: outofmemory\n", __func__, __LINE__);
			goto realloc_buffer_fail;
		}

		workingset_recycle_record(record);
		if (header.playload_length != kernel_read(filp, sizeof(header), playload, header.playload_length)) {
			pr_err("%s line %d: kernel_read failed!\n", __func__, __LINE__);
			vunmap(playload);
			workingset_free_record_exclude_filespath(record);
			goto vmap_fail;
		}

		if (header.playload_checksum != workingset_crc32c(0, playload, header.playload_length)) {
			pr_err("%s line %d: workingset_crc32c failed!\n", __func__, __LINE__);
			vunmap(playload);
			workingset_free_record_exclude_filespath(record);
			goto vmap_fail;
		}

		if (record->data.page_array) {
			vunmap(record->data.file_array);
			kfree(record->data.page_array);
		}
		record->data.page_array = page_array;
		record->data.array_page_cnt = playload_pages;
	} else {
		playload = vmap(record->data.page_array, playload_pages, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
		if (!playload) {
			pr_err("%s: out of space, vmap %u pages failed!\n", __func__, playload_pages);
			goto alloc_array_fail;
		}

		if (workingset_record_realloc_ownerbuffer_if_need(&record->owner, owner)) {
			pr_err("%s line %d: outofmemory\n", __func__, __LINE__);
			goto realloc_buffer_fail;
		}

		workingset_recycle_record(record);
		if (header.playload_length != kernel_read(filp, sizeof(header), playload, header.playload_length)) {
			pr_err("%s line %d: kernel_read failed!\n", __func__, __LINE__);
			vunmap(playload);
			workingset_free_record_exclude_filespath(record);
			goto vmap_fail;
		}

		if (header.playload_checksum != workingset_crc32c(0, playload, header.playload_length)) {
			pr_err("%s line %d: workingset_crc32c failed!\n", __func__, __LINE__);
			vunmap(playload);
			workingset_free_record_exclude_filespath(record);
			goto vmap_fail;
		}

		vunmap(record->data.file_array);
		idx = record->data.array_page_cnt;
		while (idx-- > playload_pages) {
			__free_page(record->data.page_array[idx]);
			record->data.page_array[idx] = NULL;
		}
		record->data.array_page_cnt = playload_pages;
	}

	record->state = E_RECORD_STATE_USED | E_RECORD_STATE_DATA_FROM_BACKUP;
	record->owner.uid = owner->uid;
	memcpy(record->owner.name, owner->name, strlen(owner->name) + 1);
	memcpy(record->owner.record_path, owner->record_path, strlen(owner->record_path) + 1);
	record->data.file_cnt = header.file_cnt;
	record->data.pageseq_cnt = header.pageseq_cnt;
	record->data.page_sum = header.page_sum;
	record->data.file_array = playload;
#ifdef CONFIG_TASK_DELAY_ACCT
	record->leader_blkio_cnt = header.leader_blkio_cnt;
	record->need_update = header.need_update;
#endif
	pathnode_size = sizeof(struct s_path_node) * header.file_cnt;
	for (idx = 0; idx < header.file_cnt; idx++) {
		if (!record->data.file_array[idx].path)
			continue;
		record->data.file_array[idx].path = playload + pathnode_size + len;
		len += record->data.file_array[idx].pathlen + 1;
	}
	record->data.cacheseq = playload + pathnode_size + len;
	spin_lock(&g_workingset_list_lock);
	g_workingset_cnt++;
	list_add(&record->list, &g_workingset_list);
	spin_unlock(&g_workingset_list_lock);
	mutex_unlock(&record->mutex);

	filp_close(filp, NULL);
	workingset_debug("%s: read record data from %s completely!\n", __func__, owner->record_path);
	return record;

realloc_buffer_fail:
	vunmap(playload);
vmap_fail:
	if (page_array) {
		while (idx-- > record->data.array_page_cnt) {
			__free_page(page_array[idx]);
		}
		kfree(page_array);
	}
alloc_array_fail:
	if (!is_replace) {
		mutex_unlock(&record->mutex);
		kfree(record);
	} else {
		spin_lock(&g_workingset_list_lock);
		g_workingset_cnt++;
		list_add_tail(&record->list, &g_workingset_list);
		spin_unlock(&g_workingset_list_lock);
		mutex_unlock(&record->mutex);
	}
out:
	filp_close(filp, NULL);
	return NULL;
}

/** workingset_get_existed_record - find the record of owner from cache or blockdev
* @owner: the owner of record that we will be find.
* @onlycache: don't get record from disk if it is true.
*
* we adjust the record to the head of list when we found it.
*/
static struct s_workingset_record* workingset_get_existed_record(struct s_workingset_owner *owner, bool onlycache)
{
	struct s_workingset_record *record = NULL;
	struct list_head *pos;
	struct list_head *head = &g_workingset_list;

	if (!owner->name)
		return NULL;

	spin_lock(&g_workingset_list_lock);
	list_for_each(pos, head) {
		record = container_of(pos, struct s_workingset_record, list);
		if ((record->state & E_RECORD_STATE_USED)
			&& (record->owner.uid == owner->uid)
			&& !strcmp(record->owner.name, owner->name)) {
			break;
		}
	}

	if (pos != head) {
		list_move(pos, head);
		spin_unlock(&g_workingset_list_lock);
		return record;
	} else if (!onlycache && owner->record_path) {
		spin_unlock(&g_workingset_list_lock);
		return workingset_get_record_from_backup(owner);
	} else {
		spin_unlock(&g_workingset_list_lock);
		return NULL;
	}
}

static void workingset_destroy_data(struct s_workingset *workingset, bool is_locked)
{
	struct list_head *head;
	struct s_file_info *fileinfo;

	if (!is_locked)
		mutex_lock(&workingset->mutex);

	head = &workingset->file_list;
	while (!list_empty(head)) {
		fileinfo = list_first_entry(head, struct s_file_info, list);
		list_del(&fileinfo->list);
		fileinfo->rbroot = RB_ROOT;
		if (fileinfo->path_node.path)
			kfree(fileinfo->path_node.path);

		if (fileinfo->filp_list) {
			struct s_filp_list *curr, *next;

			curr = fileinfo->filp_list;
			do {
				next = curr->next;
				if (curr->filp)
					fput(curr->filp);
				kfree(curr);
				curr = next;
			} while (curr);
		}

		kfree(fileinfo);
	}

	workingset->owner.uid = 0;
	if (workingset->owner.name) {
		kfree(workingset->owner.name);
		workingset->owner.name = NULL;
	}
	if (workingset->owner.record_path) {
		kfree(workingset->owner.record_path);
		workingset->owner.record_path = NULL;
	}
	workingset->repeated_count = 0;
	workingset->page_sum = 0;
#ifdef CONFIG_TASK_DELAY_ACCT
	workingset->leader_blkio_cnt = 0;
	workingset->leader_blkio_base = 0;
#endif
	workingset->file_count = 0;
	workingset->pageseq_count = 0;
	workingset->pagecache_alloc_index = 0;
	if (!is_locked)
		mutex_unlock(&workingset->mutex);
}

static inline struct s_workingset *css_workingset(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct s_workingset, css) : NULL;
}

static inline struct s_workingset *task_workingset(struct task_struct *task)
{
	return css_workingset(task_css(task, workingset_cgrp_id));
}

static const char *workingset_state_strs(unsigned int state)
{
	unsigned monitor_state;

	switch(state) {
		case E_CGROUP_STATE_MONITOR_INWORKING:
			monitor_state = E_MONITOR_STATE_INWORKING;
			break;
		case E_CGROUP_STATE_MONITOR_PAUSED:
			monitor_state = E_MONITOR_STATE_PAUSED;
			break;
		case E_CGROUP_STATE_MONITOR_PREREAD:
			monitor_state = E_MONITOR_STATE_PREREAD;
			break;
		case E_CGROUP_STATE_MONITOR_BACKUP:
			monitor_state = E_MONITOR_STATE_BACKUP;
			break;
		case E_CGROUP_STATE_MONITOR_STOP:
			monitor_state = E_MONITOR_STATE_STOP;
			break;
		case E_CGROUP_STATE_MONITOR_ABORT:
			monitor_state = E_MONITOR_STATE_ABORT;
			break;
		default:
			monitor_state = E_MONITOR_STATE_OUTOFWORK;
			break;
	}

	return moniter_states[monitor_state];
};

static struct cgroup_subsys_state *
workingset_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct s_workingset *workingset;

	/**
	* we alloc a page for saving struct s_workingset, because it need save pointer of pages
	* that caching page offset range information
	*/
	workingset = (struct s_workingset *)get_zeroed_page(GFP_KERNEL | __GFP_HIGHMEM);
	if (!workingset) {
		return ERR_PTR(-ENOMEM);
	}

	mutex_init(&workingset->mutex);
	return &workingset->css;
}

/**
 * workingset_css_online - commit creation of a workingset css
 * @css: css being created
 *
 */
static int workingset_css_online(struct cgroup_subsys_state *css)
{
	struct s_workingset *workingset = css_workingset(css);

	mutex_lock(&workingset->mutex);
	workingset->state = E_CGROUP_STATE_ONLINE;
	workingset->file_count = 0;
	workingset->pageseq_count = 0;
	workingset->repeated_count = 0;
	workingset->page_sum = 0;
#ifdef CONFIG_TASK_DELAY_ACCT
	workingset->leader_blkio_cnt = 0;
	workingset->leader_blkio_base = 0;
#endif
	workingset->pagecache_alloc_index = 0;
	INIT_LIST_HEAD(&workingset->file_list);

	if (0 == workingset_register_shrinker(workingset))
		workingset->shrinker_enabled = true;
	else
		workingset->shrinker_enabled = false;

	mutex_unlock(&workingset->mutex);
	return 0;
}

/**
 * workingset_css_offline - initiate destruction of a workingset css
 * @css: css being destroyed
 *
 */
static void workingset_css_offline(struct cgroup_subsys_state *css)
{
	struct s_workingset *workingset = css_workingset(css);

	mutex_lock(&workingset->mutex);

	workingset->state = E_CGROUP_STATE_OFFLINE;
	workingset_destroy_data(workingset, true);

	workingset_unregister_shrinker(workingset);

	mutex_unlock(&workingset->mutex);
}

static void workingset_css_free(struct cgroup_subsys_state *css)
{
	free_page((unsigned long)css_workingset(css));
}

#ifdef CONFIG_TASK_DELAY_ACCT
static void workingset_blkio_monitor_locked(struct s_workingset *workingset, unsigned monitor_state)
{
	if (E_CGROUP_STATE_MONITOR_INWORKING == monitor_state
		|| E_CGROUP_STATE_MONITOR_PAUSED == monitor_state
		|| E_CGROUP_STATE_MONITOR_STOP == monitor_state) {
		struct task_struct *tsk;

		rcu_read_lock();
		tsk = find_task_by_vpid(workingset->owner.pid);
		if (!tsk) {
			rcu_read_unlock();
			return;
		}

		get_task_struct(tsk);
		rcu_read_unlock();

		if (E_CGROUP_STATE_MONITOR_INWORKING == monitor_state)
			workingset->leader_blkio_base = tsk->delays->blkio_count;
		else if (tsk->delays->blkio_count > workingset->leader_blkio_base)
			workingset->leader_blkio_cnt += (unsigned short)(tsk->delays->blkio_count - workingset->leader_blkio_base);

#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
		pr_info("%s, the pid of leader=%d, leader_blkio_base = %u, leader_blkio_cnt = %u, current blkio = %u\n",
						__func__, workingset->owner.pid, workingset->leader_blkio_base, workingset->leader_blkio_cnt, tsk->delays->blkio_count);
#endif
		put_task_struct(tsk);
	}
}
#endif

/**
 * workingset_apply_state - apply state change to a single cgroup_workingset
 * @workingset: workingset to apply state change to
 * @monitor_state: the state of monitor of workingset.
 *
 * Set @state on @workingset according to @monitor_state, and perform
 * inworking or outwork as necessary.
 */
static void workingset_apply_state(struct s_workingset *workingset, unsigned monitor_state)
{
	mutex_lock(&workingset->mutex);
	if (workingset->state & E_CGROUP_STATE_ONLINE) {
#ifdef CONFIG_TASK_DELAY_ACCT
		if ((monitor_state & E_CGROUP_STATE_MONITORING)
			&& !(workingset->state & E_CGROUP_STATE_MONITORING)) {
			workingset_blkio_monitor_locked(workingset, monitor_state);
		} else if ((workingset->state & E_CGROUP_STATE_MONITORING)
			&& !(monitor_state & E_CGROUP_STATE_MONITORING)) {
			workingset_blkio_monitor_locked(workingset, monitor_state);
		}
#endif
		workingset->state &= ~E_CGROUP_STATE_MONITOR_BITMASK;
		workingset->state |= monitor_state;
	}
	mutex_unlock(&workingset->mutex);
}

/**
 * workingset_change_state - change the enter or exit state of a cgroup_workingset
 * @workingset: workingset of interest
 * @monitor_state: the state of monitor of workingset.
 *
 * The operations are recursive - all descendants of @workingset will be affected.
 */
static void workingset_change_state(struct s_workingset *workingset, unsigned monitor_state)
{
	struct cgroup_subsys_state *pos;

	rcu_read_lock();
	css_for_each_descendant_pre(pos, &workingset->css) {
		struct s_workingset *pos_f = css_workingset(pos);

		if (!css_tryget_online(pos))
			continue;
		rcu_read_unlock();

		workingset_apply_state(pos_f, monitor_state);

		rcu_read_lock();
		css_put(pos);
	}
	rcu_read_unlock();
}

static ssize_t workingset_state_write(struct kernfs_open_file *of,
			     char *buf, size_t nbytes, loff_t off)
{
	unsigned monitor_state;
	struct s_workingset *workingset = css_workingset(of_css(of));
	buf = strstrip(buf);

	if (strcmp(buf, workingset_state_strs(E_CGROUP_STATE_MONITOR_INWORKING)) == 0) {
		monitor_state = E_CGROUP_STATE_MONITOR_INWORKING;
		spin_lock(&workingset_collector->lock);
		if (workingset_collector->monitor && workingset_collector->monitor != workingset) {
			spin_unlock(&workingset_collector->lock);
			return -EBUSY;
		}
		workingset_collector->monitor = workingset;
		spin_unlock(&workingset_collector->lock);
	} else if (strcmp(buf, workingset_state_strs(E_CGROUP_STATE_MONITOR_PAUSED)) == 0) {
		monitor_state = E_CGROUP_STATE_MONITOR_PAUSED;
	} else if (strcmp(buf, workingset_state_strs(E_CGROUP_STATE_MONITOR_STOP)) == 0) {
		monitor_state = E_CGROUP_STATE_MONITOR_STOP;
	} else if (strcmp(buf, workingset_state_strs(E_CGROUP_STATE_MONITOR_ABORT)) == 0) {
		monitor_state = E_CGROUP_STATE_MONITOR_ABORT;
	} else if (strcmp(buf, workingset_state_strs(E_CGROUP_STATE_MONITOR_PREREAD)) == 0) {
		monitor_state = E_CGROUP_STATE_MONITOR_PREREAD;
	} else if (strcmp(buf, workingset_state_strs(E_CGROUP_STATE_MONITOR_BACKUP)) == 0) {
		workingset_writeback_all_records();
		return nbytes;
	}
	else
		return -EINVAL;

	workingset_debug("%s: uid=%u, name=%s, old_state=%s\n", __func__, workingset->owner.uid, workingset->owner.name, workingset_state_strs(workingset->state));
	if (monitor_state != E_CGROUP_STATE_MONITOR_PREREAD)
		workingset_change_state(workingset, monitor_state);

	if (monitor_state == E_CGROUP_STATE_MONITOR_PREREAD
		|| monitor_state == E_CGROUP_STATE_MONITOR_STOP
		|| monitor_state == E_CGROUP_STATE_MONITOR_ABORT) {
		struct s_workingset_record *record;

		mutex_lock(&workingset->mutex);
		record = workingset_get_existed_record(&workingset->owner, false);
		mutex_unlock(&workingset->mutex);

		if (record)  {
			if (monitor_state == E_CGROUP_STATE_MONITOR_ABORT)
				atomic_set(&g_preread_abort, 1);

			mutex_lock(&record->mutex);
			if ((monitor_state == E_CGROUP_STATE_MONITOR_PREREAD)
				&& !(record->state & E_RECORD_STATE_PREREADING)) {
				record->state |= E_RECORD_STATE_PREREADING;
				workingset_prereader_do_work_locked(record);
			} else if (monitor_state == E_CGROUP_STATE_MONITOR_STOP) {
				workingset_stop_preread_record_locked(record);
				record->state &= ~E_RECORD_STATE_PREREADING;
			} else if (monitor_state == E_CGROUP_STATE_MONITOR_ABORT) {
				workingset_stop_preread_record_locked(record);
				record->state &= ~(E_RECORD_STATE_PREREADING | E_RECORD_STATE_UPDATE_BASE_BLKIO);
				atomic_set(&g_preread_abort, 0);
			}
			mutex_unlock(&record->mutex);
		}
	}

	if ((monitor_state == E_CGROUP_STATE_MONITOR_STOP)
		|| (monitor_state == E_CGROUP_STATE_MONITOR_PAUSED)) {
		/*migrate all tasks from current cgoup to root, because we don't monitor they no longer.
		and notify the collector*/
		if (cgroup_transfer_tasks(of_css(of)->parent->cgroup, of_css(of)->cgroup))
			pr_err("%s, move all tasks to parent failed\n", __func__);

		if (monitor_state == E_CGROUP_STATE_MONITOR_STOP) {
			spin_lock(&workingset_collector->lock);
			workingset_collector->wait_flag = F_RECORD_PENDING;
			if (waitqueue_active(&workingset_collector->collect_wait)) {
				wake_up_interruptible_all(&workingset_collector->collect_wait);
			}
			spin_unlock(&workingset_collector->lock);
		}
	} else if (E_CGROUP_STATE_MONITOR_ABORT == monitor_state) {
		/*migrate all tasks from current cgoup to root, because we don't monitor they no longer.
		and discard the collected pagecache info*/
		if (cgroup_transfer_tasks(of_css(of)->parent->cgroup, of_css(of)->cgroup))
			pr_err("%s, move all tasks to parent failed\n", __func__);

		workingset_destroy_data(workingset, false);

		spin_lock(&workingset_collector->lock);
		if (workingset_collector->monitor == workingset) {
			workingset_collector->monitor = NULL;
			workingset_collector->read_pos = workingset_collector->write_pos = 0;
			workingset_collector->discard_count = 0;
		}
		spin_unlock(&workingset_collector->lock);
	}


	/*writeback a dirty record when we preread completely*/
	if (monitor_state == E_CGROUP_STATE_MONITOR_PREREAD)
		workingset_writeback_last_record_if_need();
	workingset_debug("%s: uid=%u, name=%s, new_state=%s\n", __func__, workingset->owner.uid, workingset->owner.name, workingset_state_strs(workingset->state));

	return nbytes;
}

static int workingset_state_read(struct seq_file *m, void *v)
{
	struct cgroup_subsys_state *css = seq_css(m);

	seq_puts(m, workingset_state_strs(css_workingset(css)->state));
	seq_putc(m, '\n');
	return 0;
}

/**workingset_data_parse_owner - parse information of the owner of workingset from the comming string.
* @workingset workingset the owner working on.
* @owner_string the comming string.
*
**/
static int workingset_data_parse_owner(struct s_workingset *workingset, char *owner_string)
{
	int ret = 0;
	char *str = owner_string;
	char *token;
	int pid;
	unsigned uid, len;
	char *owner_name;
	char *record_path;

	//the 1th: uid
	token = strsep(&str, " ");
	if (token == NULL || str == NULL) {
		ret = - EINVAL;
		goto out;
	}
	ret = kstrtouint(token, 0, &uid);
	if (ret)
		goto out;

	//the 2th: pid
	token = strsep(&str, " ");
	if (token == NULL || str == NULL) {
		ret = - EINVAL;
		goto out;
	}
	ret = kstrtouint(token, 0, &pid);
	if (ret)
		goto out;

	//the 3th: name of owner
	token = strsep(&str, " ");
	if (token == NULL || str == NULL) {
		ret = - EINVAL;
		goto out;
	}
	len = strlen(token);
	if (len <= 0) {
		ret = - EINVAL;
		goto out;
	}
	owner_name = (char*)kzalloc(len + 1, GFP_KERNEL);
	if (!owner_name) {
		ret = - ENOMEM;
		goto out;
	}
	strncpy(owner_name, token, len);
	owner_name[len] = '\0';

	//the 4th: the path of record
	len = strlen(str);
	if (len <= 0) {
		ret = - EINVAL;
		goto parse_path_failed;
	}
	record_path = (char*)kzalloc(len + 1, GFP_KERNEL);
	if (!record_path) {
		ret = - ENOMEM;
		goto parse_path_failed;
	}
	strncpy(record_path, str, len);
	record_path[len] = '\0';

	mutex_lock(&workingset->mutex);
	workingset->owner.uid = uid;
	workingset->owner.pid = pid;

	if (workingset->owner.name)
		kfree(workingset->owner.name);
	workingset->owner.name = owner_name;

	if (workingset->owner.record_path)
		kfree(workingset->owner.record_path);
	workingset->owner.record_path = record_path;
	mutex_unlock(&workingset->mutex);
	return 0;

parse_path_failed:
	kfree(owner_name);
out:
	return ret;
}

static ssize_t workingset_data_write(struct kernfs_open_file *of,
			     char *buf, size_t nbytes, loff_t off)
{
	int ret;

	buf = strstrip(buf);
	ret = workingset_data_parse_owner(css_workingset(of_css(of)), buf);
	if (ret)
		return 0;
	else
		return nbytes;
}

static int workingset_data_read(struct seq_file *m, void *v)
{
	struct cgroup_subsys_state *css = seq_css(m);
	struct s_workingset *workingset = css_workingset(css);
	struct s_workingset_record *record;

	mutex_lock(&workingset->mutex);
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
	seq_printf(m, "Uid: %u\n", workingset->owner.uid);
	seq_printf(m, "Pid: %d\n", workingset->owner.pid);
	seq_printf(m, "Name: %s\n", workingset->owner.name? workingset->owner.name : "Unknow");
	seq_printf(m, "RecordPath: %s\n", workingset->owner.record_path? workingset->owner.record_path : "Unknow");
#endif
	record = workingset_get_existed_record(&workingset->owner, false);
#ifdef CONFIG_TASK_DELAY_ACCT
	seq_printf(m, "RecordState:%s\n", !record? "none" : (record->need_update? "older" : "uptodate"));
#else
	seq_printf(m, "RecordState:%s\n", !record? "none" : "uptodate");
#endif
	mutex_unlock(&workingset->mutex);

	return 0;
}

static struct cftype files[] = {
	{
		.name = "state",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = workingset_state_read,
		.write = workingset_state_write,
	},
	{
		.name = "data",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = workingset_data_read,
		.write = workingset_data_write,
	},
	{ }	/* terminate */
};

struct cgroup_subsys workingset_cgrp_subsys = {
	.css_alloc	= workingset_css_alloc,
	.css_online	= workingset_css_online,
	.css_offline	= workingset_css_offline,
	.css_free	= workingset_css_free,
	.legacy_cftypes	= files,
};

static int get_file_path_and_hashcode(struct file *file, char* buf, unsigned int buf_size, char **str_path, int *len, unsigned int *hashcode)
{
	int path_len;
	char *file_path;

	file_path = d_path(&file->f_path, buf, buf_size - 1);
	if (IS_ERR_OR_NULL(file_path)) {
		return -1;
	}

	path_len = strlen(file_path);
	*str_path = file_path;
	*len = path_len;
	*hashcode = workingset_crc32c(0, file_path, path_len);
	return 0;
}

static int workingset_record_fileinfo_if_need_locked(struct s_workingset *workingset, struct file *file, struct s_file_info **file_info, bool *is_existed)
{
	int ret = 0;
	int seq_num = 0;
	bool existed = false;
	struct s_file_info *fileinfo;
	struct inode	*inode = file->f_mapping->host;
	struct s_filp_list *filp_list;
	struct list_head *pos;
	struct list_head *head;
	int path_len;
	char *file_path;
	unsigned hashcode;
	char buf[PATH_MAX_CHAR] = {'\0',};

	if (workingset->pageseq_count >= MAX_TOUCHED_PAGES_COUNT) {
		ret = -ENOSPC;
		goto out;
	}

	//first, match inode when search same file
	head = &workingset->file_list;
	list_for_each(pos, head) {
		fileinfo = container_of(pos, struct s_file_info, list);
		filp_list = fileinfo->filp_list;
		while (filp_list) {
			if (filp_list->filp->f_mapping->host == inode) {
				existed = true;
				goto done;
			}
			filp_list = filp_list->next;
		}
		seq_num++;
	}

	if (!existed) {
		gfp_t gfp_mask = GFP_KERNEL;

		//get the path string of file and hashcode of path string.
		if (get_file_path_and_hashcode(file, buf, PATH_MAX_CHAR, &file_path, &path_len, &hashcode)) {
			pr_warning("%s, get_file_path_and_hashcode failed!\n", __func__);
			ret = -EINVAL;
			goto out;
		}

		//second, match hashcode and string when search same file
		seq_num = 0;
		list_for_each(pos, head) {
			fileinfo = container_of(pos, struct s_file_info, list);
			if ((fileinfo->path_node.hashcode == hashcode)
				    && !strcmp(fileinfo->path_node.path, file_path)) {
				workingset_debug("%s, %s has multi inodes! inode=%p\n", __func__, file_path, inode);
				filp_list = (struct s_filp_list*)kzalloc(sizeof(struct s_filp_list), gfp_mask);
				if (filp_list) {
					struct s_filp_list *temp = fileinfo->filp_list;
					while (temp->next) {
						temp = temp->next;
					}
					filp_list->filp = file;
					temp->next = filp_list;
					existed = false;
				} else {
					existed = true;
				}
				goto done;
			}
			seq_num++;
		}

		if (workingset->file_count >= MAX_TOUCHED_FILES_COUNT) {
			ret = -ENOSPC;
			goto out;
		}

		fileinfo = (struct s_file_info*)kzalloc(sizeof(struct s_file_info), gfp_mask);
		if (!fileinfo) {
			ret = -ENOMEM;
			goto out;
		}

		fileinfo->path_node.path = (char *)kzalloc(path_len + 1, gfp_mask);
		if (!fileinfo->path_node.path) {
			ret = -ENOMEM;
			goto fileinfo_free;
		}
		strcpy(fileinfo->path_node.path, file_path);

		fileinfo->filp_list = (struct s_filp_list*)kzalloc(sizeof(struct s_filp_list), gfp_mask);
		if (!fileinfo->filp_list) {
			ret = -ENOMEM;
			goto filepath_free;
		}
		fileinfo->filp_list->filp = file;
		fileinfo->path_node.hashcode = hashcode;
		fileinfo->path_node.pathlen = path_len;
		fileinfo->pageseq_count = 0;
		fileinfo->rbroot = RB_ROOT;
		list_add_tail(&fileinfo->list, head);
		workingset->file_count++;
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
		pr_info("%s, include %s, size = %lld\n", __func__, file_path, round_up(i_size_read(inode), PAGE_SHIFT));
#endif
	}
done:
	ret = seq_num;
	*file_info = fileinfo;
	*is_existed = existed;
	return ret;

filepath_free:
	kfree(fileinfo->path_node.path);
fileinfo_free:
	kfree(fileinfo);
out:
	return ret;
}

static int workingset_dealwith_pagecache_locked(struct s_cachepage_info *info, struct s_workingset *workingset)
{
	int ret = 0, file_idx;
	bool is_existed_file = false;
	struct file *file = info->filp;
	unsigned offset = info->start_offset;
	int pid = info->pid;
	unsigned count = info->count;
	struct s_pagecache_info *pagecache;
	struct s_file_info *file_info = NULL;
	int major_touched;
	unsigned repeat_count;
	int page_count_delta;

	if (pid == workingset->owner.pid)
		major_touched = 1;
	else
		major_touched = 0;

	/*get position of current file in file list*/
	file_idx = workingset_record_fileinfo_if_need_locked(workingset, file, &file_info, &is_existed_file);
	if (IS_ERR(file_idx)) {
		ret = file_idx;
		goto done;
	}

	pagecache = workingset_pagecache_info_cache_alloc(workingset);
	if (!pagecache) {
		ret = -ENOMEM;
		goto done;
	}

	pagecache->offset_range.start = CREATE_HANDLE(file_idx, offset);
	pagecache->offset_range.end = CREATE_HANDLE(file_idx, (offset + count));
	/*insert page offset range to the range tree of file*/
	if (workingset_range_rb_insert(&file_info->rbroot, pagecache, major_touched, &repeat_count, &page_count_delta))
	{
		workingset->repeated_count += repeat_count;
		workingset->page_sum += count - repeat_count;
		workingset->pageseq_count += page_count_delta;
		file_info->pageseq_count += page_count_delta;
	} else {
		if (count > 1) {
			pagecache->offset_range.start |= (PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT);
			pagecache->offset_range.end |= (PAGE_RANGE_HEAD_MASK << PAGE_RANGE_HEAD_SHIFT);
			workingset->pageseq_count += 2;
			file_info->pageseq_count += 2;
		} else {
			workingset->pageseq_count += 1;
			file_info->pageseq_count += 1;
		}
		workingset->page_sum += count;
		workingset->pagecache_alloc_index++;
	}

done:
	if (ret || is_existed_file)
		fput(file);

	return ret;
}

static void workingset_collector_do_collect_locked(struct s_workingset_collector *collector)
{
	char buffer[COLLECTOR_ONCE_DEALWITH_COUNT * sizeof(struct s_cachepage_info)];
	unsigned buffer_pos;
	unsigned read_pos, write_pos;
	unsigned copy_size;
	unsigned idx;

	while (collector->read_pos != collector->write_pos) {
		read_pos = collector->read_pos;
		write_pos = collector->write_pos;

		if (read_pos > write_pos) {
			/*write pointer has beed reversed.*/
			if (COLLECTOR_CACHE_SIZE - read_pos > sizeof(buffer))
				copy_size = sizeof(buffer);
			else
				copy_size = COLLECTOR_CACHE_SIZE - read_pos;

			memcpy(buffer, collector->circle_buffer + read_pos, copy_size);
			read_pos += copy_size;
			buffer_pos = copy_size;

			/*pick data from the head of circle buffer when local buffer is not full*/
			if ((copy_size < sizeof(buffer)) && write_pos) {
				if (write_pos > (sizeof(buffer) - copy_size))
					copy_size = sizeof(buffer) - copy_size;
				else
					copy_size = write_pos;

				memcpy(buffer + buffer_pos, collector->circle_buffer, copy_size);
				buffer_pos += copy_size;
				read_pos += copy_size;
			}
		} else {
			if (write_pos - read_pos > sizeof(buffer))
				copy_size = sizeof(buffer);
			else
				copy_size = write_pos - read_pos;

			memcpy(buffer, collector->circle_buffer + read_pos, copy_size);
			read_pos += copy_size;
			buffer_pos = copy_size;
		}
		collector->read_pos = (read_pos >= COLLECTOR_CACHE_SIZE)? (read_pos - COLLECTOR_CACHE_SIZE) : read_pos;

		for (idx = 0; idx < buffer_pos; idx += sizeof(struct s_cachepage_info)) {
			struct s_workingset *workingset = collector->monitor;

			if (workingset) {
				spin_unlock(&collector->lock);
				mutex_lock(&workingset->mutex);
				workingset_dealwith_pagecache_locked((struct s_cachepage_info *)(buffer + idx), workingset);
				mutex_unlock(&workingset->mutex);
				spin_lock(&collector->lock);
			} else {
				return;
			}
		}
	}
}

static int workingset_collector_fill_record_cacheseq_locked(struct s_workingset_data *data, unsigned *cacheseq_idx,
	struct s_pagecache_info **pagecache_array, unsigned page_idx, unsigned end_in_page)
{
	int ret = 0;
	unsigned idx_in_page;
	unsigned idx = *cacheseq_idx;
	struct s_pagecache_info *pagecache;

	/**
	* In order to save memory, we save the range including single page in one word by cleaned range head bit.
	*/
	for (idx_in_page = 0; idx_in_page < end_in_page; idx_in_page++) {
		pagecache = pagecache_array[page_idx] + idx_in_page;
		if (unlikely(pagecache->offset_range.start == PAGECACHE_INVALID_OFFSET))
			continue;

		if (idx < data->pageseq_cnt) {
			data->cacheseq[idx++] = pagecache->offset_range.start;
		} else {
			pr_err("%s: idx=%u, pageseq_cnt=%u has never happend!\n", __func__, idx, data->pageseq_cnt);
			ret = -EPERM;
			break;
		}

		if ((pagecache->offset_range.start >> PAGE_RANGE_HEAD_SHIFT) &  PAGE_RANGE_HEAD_MASK) {
			if (idx < data->pageseq_cnt) {
				data->cacheseq[idx++] = pagecache->offset_range.end;
			} else {
				pr_err("%s: idx=%u, pageseq_cnt=%u has never happend!\n", __func__, idx, data->pageseq_cnt);
				ret = -EPERM;
				break;
			}
		}
	}

	*cacheseq_idx = idx;
	return ret;
}

static int workingset_collector_read_data_locked(struct s_workingset *workingset, struct s_workingset_record *record, bool is_exist)
{
	int ret;
	struct s_workingset_data *data = &record->data;
	struct page *page, **page_array;
	struct list_head *pos;
	struct list_head *head;
	struct s_file_info *fileinfo;
	struct s_pagecache_info *pagecache;
	unsigned pathnode_size;
	unsigned playload_size;
	unsigned playload_pages;
	void* playload;
	unsigned idx, handle_idx;
	unsigned page_idx, idx_in_page;

	if ((!data->page_array && data->array_page_cnt)
		|| (data->page_array && !data->array_page_cnt)) {
		pr_err("%s: page_array=%p, array_page_cnt=%u, should be never happend!\n", __func__, data->page_array, data->array_page_cnt);
		ret = -EINVAL;
		goto out;
	}

	pathnode_size = sizeof(struct s_path_node) * workingset->file_count;
	playload_size = pathnode_size + sizeof(unsigned) * workingset->pageseq_count;
	playload_pages = DIV_ROUND_UP(playload_size, PAGE_SIZE);
	/**
	* In order to avoid more direct reclaim, so we reuse the memory of old record as far as possible when replace it.
	*/
	if (data->array_page_cnt < playload_pages) {
		page_array = (struct page **)kzalloc(sizeof(struct page*) * playload_pages, GFP_KERNEL);
		if (!page_array) {
			pr_err("%s: out of memory, kzalloc %lu bytes failed!\n", __func__, sizeof(struct page*) * playload_pages);
			ret = -ENOMEM;
			goto out;
		}

		if (data->array_page_cnt)
			memcpy(page_array, data->page_array, sizeof(struct page*) * data->array_page_cnt);

		idx = data->array_page_cnt;
		while (idx < playload_pages) {
			page = alloc_page(GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO);
			if (!page) {
				pr_err("%s: out of memory, alloc %u pages failed!\n", __func__, playload_pages);
				ret = -ENOMEM;
				goto vmap_fail;
			}
			page_array[idx] = page;
			idx++;
		}

		playload = vmap(page_array, playload_pages, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
		if (!playload) {
			pr_err("%s: out of space, vmap %u pages failed!\n", __func__, playload_pages);
			ret =  -ENOSPC;
			goto vmap_fail;
		}

		if (!is_exist && workingset_record_realloc_ownerbuffer_if_need(&record->owner, &workingset->owner)) {
			ret =  -ENOMEM;
			goto vmap_fail;
		}
		workingset_recycle_record(record);
		if (data->page_array) {
			vunmap(data->file_array);
			kfree(data->page_array);
		}
		data->page_array = page_array;
		data->array_page_cnt = playload_pages;
	} else {
		playload = vmap(data->page_array, playload_pages, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
		if (!playload) {
			pr_err("%s: out of space, vmap %u pages failed!\n", __func__, playload_pages);
			ret =  -ENOSPC;
			goto out;
		}

		if (!is_exist && workingset_record_realloc_ownerbuffer_if_need(&record->owner, &workingset->owner)) {
			ret =  -ENOMEM;
			goto out;
		}
		workingset_recycle_record(record);
		vunmap(data->file_array);

		idx = data->array_page_cnt;
		while (idx-- > playload_pages) {
			__free_page(data->page_array[idx]);
			data->page_array[idx] = NULL;
		}
		data->array_page_cnt = playload_pages;
	}

	if (!is_exist) {
		record->owner.uid = workingset->owner.uid;
		memcpy(record->owner.name, workingset->owner.name, strlen(workingset->owner.name) + 1);
		memcpy(record->owner.record_path, workingset->owner.record_path, strlen(workingset->owner.record_path) + 1);
	}
	data->file_cnt = workingset->file_count;
	data->pageseq_cnt = workingset->pageseq_count;
	data->page_sum = workingset->page_sum;
	data->file_array = playload;
	data->cacheseq = playload + pathnode_size;

	idx = 0;
	handle_idx = 0;
	head = &workingset->file_list;
	list_for_each(pos, head) {
		fileinfo = container_of(pos, struct s_file_info, list);
		if (idx < data->file_cnt) {
			if (!fileinfo->pageseq_count) {
				kfree(fileinfo->path_node.path);
				memset(data->file_array + idx, 0, sizeof(struct s_path_node));
			} else {
				memcpy(data->file_array + idx, &fileinfo->path_node, sizeof(struct s_path_node));
			}
		} else if (fileinfo->path_node.path) {
			kfree(fileinfo->path_node.path);
		}
		//the pointer of path is assigned to path of record, so don't free it in here.
		fileinfo->path_node.path = NULL;
		idx++;
	}

	idx = 0;
	for (page_idx = 0; page_idx < (workingset->pagecache_alloc_index/ PAGECACHEINFO_PER_PAGE); page_idx++) {
		ret = workingset_collector_fill_record_cacheseq_locked(data, &idx,
				workingset->pagecache_array_addr, page_idx,
				PAGECACHEINFO_PER_PAGE);
		if (ret)
			goto fill_data_fail;
	}
	ret = workingset_collector_fill_record_cacheseq_locked(data, &idx,
				workingset->pagecache_array_addr, page_idx,
				(workingset->pagecache_alloc_index % PAGECACHEINFO_PER_PAGE));
	if (ret)
		goto fill_data_fail;

	record->state &= ~E_RECORD_STATE_UPDATE_HEADER_ONLY;
	record->state |= E_RECORD_STATE_USED | E_RECORD_STATE_DIRTY;
	return 0;

fill_data_fail:
	record->state &= ~(E_RECORD_STATE_USED | E_RECORD_STATE_DIRTY | E_RECORD_STATE_UPDATE_HEADER_ONLY);
	return ret;

vmap_fail:
	while (idx-- > data->array_page_cnt) {
		__free_page(page_array[idx]);
	}
	kfree(page_array);
out:
	return ret;
}

static void workingset_collector_do_record_locked(struct s_workingset *workingset, unsigned long discard_count)
{
	struct s_workingset_record *record;
	bool is_exist, is_new = false;
	int ret;
	struct list_head *pos;

	if (!workingset)
		return;

	mutex_lock(&workingset->mutex);

	workingset_debug("%s: uid=%u, name=%s, state=%s\n", __func__, workingset->owner.uid, workingset->owner.name, workingset_state_strs(workingset->state));
	if ((workingset->state & E_CGROUP_STATE_MONITOR_STOP) != E_CGROUP_STATE_MONITOR_STOP
		|| !workingset->owner.name || !workingset->owner.record_path) {
		pr_warning("%s, workingset maybe is busy!, state is %s, record_path or name of owner is null!\n", __func__, workingset_state_strs(workingset->state));
		mutex_unlock(&workingset->mutex);
		return;
	}
#ifndef CONFIG_TASK_DELAY_ACCT
	if (!workingset->file_count || !workingset->pageseq_count) {
		pr_warning("%s, the data of workingset has nothing!, file_count=%u, pageseq_count=%u, state is %s\n",
			__func__, workingset->file_count, workingset->pageseq_count, workingset_state_strs(workingset->state));
		goto out;
	}
#endif

	record = workingset_get_existed_record(&workingset->owner, true);
	if (record) {
		is_exist = true;
		mutex_lock(&record->mutex);
#ifdef CONFIG_TASK_DELAY_ACCT
		/**
		* check the effect of prereading by comparing the blkio count on main thread.
		* the empirical blkio used to deciding recollect pagecache info again.
		*/
		if (!workingset->file_count || !workingset->pageseq_count) {
			workingset_debug("%s, leader_blkio_cnt of record = %u, leader_blkio_cnt of workignset = %u\n",
						__func__, record->leader_blkio_cnt, workingset->leader_blkio_cnt);
			if (workingset->leader_blkio_cnt > (record->data.pageseq_cnt * BLKIO_PERCENTAGE_THRESHOLD_FOR_UPDATE / 100)) {
				record->need_update = 1;
				if (!(record->state & E_RECORD_STATE_DIRTY))
					record->state |= E_RECORD_STATE_DIRTY | E_RECORD_STATE_UPDATE_HEADER_ONLY;
				workingset_debug("%s, the workingset of application maybe has changed, need collect again! current blkio count = %u, count of pages = %u\n",
					__func__, workingset->leader_blkio_cnt, record->data.pageseq_cnt);
			} else if (!record->leader_blkio_cnt
				&& (record->state & E_RECORD_STATE_UPDATE_BASE_BLKIO)
				&& workingset->leader_blkio_cnt) {
				workingset_debug("%s, the workingset of application preread first! preread base blkio count = %u, current blkio count = %u\n",
					__func__, record->leader_blkio_cnt, workingset->leader_blkio_cnt);
				record->leader_blkio_cnt = workingset->leader_blkio_cnt;
				if (!(record->state & E_RECORD_STATE_DIRTY))
					record->state |= E_RECORD_STATE_DIRTY | E_RECORD_STATE_UPDATE_HEADER_ONLY;
			} else if (record->leader_blkio_cnt
					&& (workingset->leader_blkio_cnt >= CARE_BLKIO_MIN_THRESHOLD)
					&& (record->leader_blkio_cnt * 2 < workingset->leader_blkio_cnt)) {
				record->need_update = 1;
				if (!(record->state & E_RECORD_STATE_DIRTY))
					record->state |= E_RECORD_STATE_DIRTY | E_RECORD_STATE_UPDATE_HEADER_ONLY;
				workingset_debug("%s, the workingset of application maybe has changed, need collect again! preread base blkio count = %u, current blkio count = %u\n",
					__func__, record->leader_blkio_cnt, workingset->leader_blkio_cnt);
			}
			record->state &= ~E_RECORD_STATE_UPDATE_BASE_BLKIO;
			mutex_unlock(&record->mutex);
			workingset->leader_blkio_cnt = 0;
			workingset->leader_blkio_base = 0;
			goto out;
		}
		record->need_update = 0;
#endif
	} else {
#ifdef CONFIG_TASK_DELAY_ACCT
		if (!workingset->file_count || !workingset->pageseq_count) {
			pr_warning("%s, the data of workingset has nothing!, file_count=%u, pageseq_count=%u, state is %s\n",
				__func__, workingset->file_count, workingset->pageseq_count, workingset_state_strs(workingset->state));
			goto out;
		}
#endif
		is_exist = false;
		if (g_workingset_cnt < MAX_WORKINGSET_RECORDS) {
			is_new = true;
			record = (struct s_workingset_record *)kzalloc(sizeof(struct s_workingset_record), GFP_KERNEL);
		} else {
			/*if record is not existed, we replace oldest clean record in list*/
			spin_lock(&g_workingset_list_lock);
			list_for_each_prev(pos, &g_workingset_list) {
				record = container_of(pos, struct s_workingset_record, list);
				if (!(record->state & (E_RECORD_STATE_DIRTY | E_RECORD_STATE_PREREADING))) {
					break;
				}
			}
			if (pos == &g_workingset_list)
				record = NULL;
			if (record) {
				list_del(&record->list);
				g_workingset_cnt--;
				spin_unlock(&g_workingset_list_lock);
				mutex_lock(&record->mutex);
			} else {
				spin_unlock(&g_workingset_list_lock);
				pr_warning("%s, no available record can be replaced!\n", __func__);
			}
		}
	}

	if (record) {
		/*organize the collect data, and save in record*/
		if (!workingset_collector_read_data_locked(workingset, record, is_exist)) {
			if (!is_exist) {
				if (is_new)
					mutex_init(&record->mutex);

				/**
				* we'll recollect info for the second times because there were some permit dialog in the first time.
				*/
				record->need_update = 1;
				spin_lock(&g_workingset_list_lock);
				g_workingset_cnt++;
				list_add(&record->list, &g_workingset_list);
				spin_unlock(&g_workingset_list_lock);
			}
			workingset_debug("%s: collect %u files and %u pageseqs, sum of pages = %u, repeated_count = %lu, discard_count=%lu\n",
				__func__, record->data.file_cnt, record->data.pageseq_cnt, workingset->page_sum, workingset->repeated_count, discard_count);
		} else if (is_new) {
			kfree(record);
		} else if (!is_exist) {
			spin_lock(&g_workingset_list_lock);
			g_workingset_cnt++;
			list_add_tail(&record->list, &g_workingset_list);
			spin_unlock(&g_workingset_list_lock);
		}
		if (!is_new)
			mutex_unlock(&record->mutex);
	}

	workingset_destroy_data(workingset, true);
out:
	spin_lock(&workingset_collector->lock);
	if (workingset_collector->monitor == workingset) {
		workingset_collector->monitor = NULL;
		workingset_collector->read_pos = workingset_collector->write_pos = 0;
		workingset_collector->discard_count = 0;
	}
	spin_unlock(&workingset_collector->lock);
	workingset->state = E_CGROUP_STATE_MONITOR_OUTOFWORK;
	mutex_unlock(&workingset->mutex);
}

static void workingset_collector_do_work(struct s_workingset_collector *collector)
{
	enum workingset_wait_flags wait_flag;

	spin_lock(&collector->lock);
	wait_flag = collector->wait_flag;
	collector->wait_flag = F_NONE;
	if (wait_flag == F_COLLECT_PENDING) {
		workingset_collector_do_collect_locked(collector);
		spin_unlock(&collector->lock);
	 } else if (wait_flag == F_RECORD_PENDING) {
		struct s_workingset *monitor = collector->monitor;
		unsigned long discard_count = collector->discard_count;

		collector->discard_count = 0;
		spin_unlock(&collector->lock);
		workingset_collector_do_record_locked(monitor, discard_count);
	} else {
		spin_unlock(&collector->lock);
	}
}

/**
 * workingset_page_cache_read - adds requested page to the page cache if not already there
 * @file:	file to read
 * @offset:	page index
 *
 * This adds the requested page to the page cache if it isn't already there,
 * and schedules an I/O to read in its contents from disk.
 */
static int workingset_page_cache_read(struct s_readpages_control *rpc)
{
	struct file *file = rpc->filp;
	struct address_space *mapping = rpc->mapping;
	pgoff_t offset = rpc->offset;
	struct page *page;
	int ret;

#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
	rpc->lastpage = NULL;
#endif
	do {
		page = alloc_pages(mapping_gfp_mask(mapping) | __GFP_RECLAIM | __GFP_IO | __GFP_COLD, 0);
		if (!page) {
			pr_err("%s: out of memory!\n", __func__);
			return -ENOMEM;
		}

		ret = add_to_page_cache_lru(page, mapping, offset, GFP_KERNEL);
		if (ret == 0) {
			ret = mapping->a_ops->readpage(file, page);
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
			if (!ret)
				rpc->lastpage = page;
#endif
		} else if (ret == -EEXIST)
			ret = 0; /* losing race to add is OK */

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
		put_page(page);
#else
		page_cache_release(page);
#endif
	} while (ret == AOP_TRUNCATED_PAGE);

	return ret;
}

/**
 * workingset_adjust_page_lru - move inactive page to head of the lru list.
 * @page:	page to move
 *
 */
static bool workingset_adjust_page_lru(struct page *page)
{
	bool adjusted = false;

	if (!PageUnevictable(page)
#ifdef CONFIG_TASK_PROTECT_LRU
		&& !PageProtect(page)
#endif
		&& !PageActive(page)) {
		if (PageLRU(page)) {
			struct lruvec *lruvec;
			struct zone *zone = page_zone(page);

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
			spin_lock_irq(zone_lru_lock(zone));
#else
			spin_lock_irq(&zone->lru_lock);
#endif
			lruvec = mem_cgroup_page_lruvec(page, zone);
#ifdef CONFIG_TASK_PROTECT_LRU
			if (PageLRU(page) && !PageProtect(page) && !PageSwapBacked(page)) {
				list_move(&page->lru, &lruvec->heads[PROTECT_HEAD_END].protect_page[page_lru(page)].lru);
				adjusted = true;
			}
#else
			if (PageLRU(page) && !PageSwapBacked(page)) {
				list_move(&page->lru, &lruvec->lists[page_lru(page)]);
				adjusted = true;
			}
#endif
#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
			spin_unlock_irq(zone_lru_lock(zone));
#else
			spin_unlock_irq(&zone->lru_lock);
#endif
		} else {
			mark_page_accessed(page);
			adjusted = true;
		}
	}
	return adjusted;
}

/**
 * workingset_read_pages - read contiguous filepage from disk.
 */
static int workingset_read_pages(struct address_space *mapping, struct file *filp,
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
		struct page **lastpage,
#endif
		struct list_head *pages, unsigned nr_pages)
{
	struct blk_plug plug;
	unsigned page_idx;
	int ret;

	blk_start_plug(&plug);

	if (mapping->a_ops->readpages) {
		struct page *page = list_entry((pages)->next, struct page, lru);
		ret = mapping->a_ops->readpages(filp, mapping, pages, nr_pages);
		/* Clean up the remaining pages */
		put_pages_list(pages);
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
		if (!ret)
			*lastpage = page;
#endif
		goto out;
	}

	for (page_idx = 0; page_idx < nr_pages; page_idx++) {
		struct page *page = list_entry((pages)->prev, struct page, lru);
		list_del(&page->lru);
		if (!add_to_page_cache_lru(page, mapping, page->index,
				mapping_gfp_constraint(mapping, GFP_KERNEL))) {
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
			if (!mapping->a_ops->readpage(filp, page))
				*lastpage = page;
#else
			mapping->a_ops->readpage(filp, page);
#endif
		}
#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
		put_page(page);
#else
		page_cache_release(page);
#endif
	}
	ret = 0;

out:
	blk_finish_plug(&plug);

	return ret;
}

/**
 * workingset_page_cache_range_read - read contiguous filepage.
 */
int workingset_page_cache_range_read(struct s_readpages_control *rpc)
{
	LIST_HEAD(page_pool);
	int page_idx;
	int ret = 0;
	struct file *filp = rpc->filp;
	struct address_space *mapping = rpc->mapping;
	pgoff_t offset = rpc->offset;
	unsigned long nr_to_read = rpc->nr_to_read;
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long end_index;	/* The last page we want to read */
	loff_t isize = i_size_read(inode);
	unsigned nr_adj = 0;

#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
	rpc->lastpage = NULL;
#endif
	if (isize == 0)
		goto out;

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
	end_index = ((isize - 1) >> PAGE_SHIFT);
#else
	end_index = ((isize - 1) >> PAGE_CACHE_SHIFT);
#endif

	/*
	 * Preallocate as many pages as we will need.
	 */
	for (page_idx = 0; page_idx < nr_to_read; page_idx++) {
		pgoff_t page_offset = offset + page_idx;

		if (page_offset > end_index)
			break;

		page = find_get_page(mapping, page_offset);
		if (page) {
			if (workingset_adjust_page_lru(page))
				nr_adj++;
			put_page(page);
			continue;
		}

		page = alloc_pages(mapping_gfp_mask(mapping) | __GFP_RECLAIM | __GFP_IO | __GFP_COLD, 0);
		if (!page) {
			pr_err("%s: out of memory!\n", __func__);
			break;
		}
		page->index = page_offset;
		list_add(&page->lru, &page_pool);
		ret++;
	}

	/*
	 * Now start the IO.  We ignore I/O errors - if the page is not
	 * uptodate then the caller will launch readpage again, and
	 * will then handle the error.
	 */
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
	if (ret)
		workingset_read_pages(mapping, filp, &rpc->lastpage, &page_pool, ret);
#else
	if (ret)
		workingset_read_pages(mapping, filp, &page_pool, ret);
#endif

	WARN_ON(!list_empty(&page_pool));

out:
	rpc->nr_adjusted = nr_adj;
	return ret;
}

static void workingset_prereader_do_work_locked(struct s_workingset_record *to_preread)
{
	unsigned idx, file_idx;
	struct file **filpp;
	struct page *page;
	struct s_readpages_control rpc;
	bool preread_major_page = true;
	bool is_major_page;
	unsigned range_end;
	int flags = O_RDONLY;
	unsigned present_pages_cnt = 0;
	unsigned read_count;
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
	struct page *lastpage = NULL;
	u64 time_start, time_end;
#endif
	unsigned read_pages_cnt = 0;
	unsigned move_lru_cnt = 0;
	unsigned major_cnt = 0;
	unsigned waste_cnt = 0;
	struct s_workingset_data *data = &to_preread->data;

	if (!data->file_cnt || !data->pageseq_cnt || !data->file_array || !data->cacheseq)
		return;

	if (atomic_read(&g_preread_abort))
		return;

#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
	time_start = ktime_get_ns();
#endif

	/*alloc pages for save opened struct files*/
   	if (data->file_cnt > FILPS_PER_PAGE) {
		int need_pages = (data->file_cnt + FILPS_PER_PAGE - 1) / FILPS_PER_PAGE;

		for (idx = 0; idx < need_pages; idx++) {
			page = alloc_page(GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO);
			if (!page) {
				pr_err("%s: out of memory, alloc %u pages failed!\n", __func__, need_pages);
				break;
			}
			to_preread->filp_pages[idx] = page;
		}

		if (idx >= need_pages)
			to_preread->preread_filpp = filpp = (struct file **)vmap(to_preread->filp_pages, need_pages, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
		else
			filpp = NULL;

		if (!filpp) {
			for (idx = 0; idx < need_pages; idx++) {
				if (to_preread->filp_pages[idx]) {
					__free_page(to_preread->filp_pages[idx]);
					to_preread->filp_pages[idx] = NULL;
				}
			}
			return;
		}
   	} else {
		to_preread->preread_filpp = filpp = (struct file **)get_zeroed_page(GFP_KERNEL | __GFP_HIGHMEM);
		if (!filpp)
			return;
   	}

	if (force_o_largefile())
		flags |= O_LARGEFILE;

	/*in some case, io request is congested, so we must be ensure read file page of main thread touched first*/
try_next:
	for (idx = 0; idx < data->pageseq_cnt; idx++) {
		if (!(idx%100) && atomic_read(&g_preread_abort))
			return;
		file_idx = (data->cacheseq[idx] >> FILE_OFFSET_BITS) & MAX_TOUCHED_FILES_COUNT;
		is_major_page = data->cacheseq[idx] & (PAGE_MAJOR_MASK << PAGE_MAJOR_SHIFT);
		if ((preread_major_page && !is_major_page)
			|| (!preread_major_page && is_major_page))
			continue;

		if (is_major_page)
			major_cnt++;
		if ((file_idx >= data->file_cnt) || !data->file_array[file_idx].path)
			continue;

		if (!filpp[file_idx]) {
			filpp[file_idx] = filp_open(data->file_array[file_idx].path, flags, 0);
			if (IS_ERR_OR_NULL(filpp[file_idx])) {
				workingset_debug("%s: open %s failed! err = %d\n", __func__, data->file_array[file_idx].path, PTR_ERR(filpp[file_idx]));
				if (!(to_preread->state & E_RECORD_STATE_DATA_FROM_BACKUP))
					kfree(data->file_array[file_idx].path);
				data->file_array[file_idx].path = NULL;
				filpp[file_idx] = NULL;
				continue;
			}
		}
		//find file page in page cache.
		rpc.filp = filpp[file_idx];
		rpc.mapping = filpp[file_idx]->f_mapping;
		rpc.offset = data->cacheseq[idx] & MAX_TOUCHED_FILE_OFFSET;
		if ((data->cacheseq[idx] >> PAGE_RANGE_HEAD_SHIFT) &  PAGE_RANGE_HEAD_MASK) {
			/*in the case, prereading multi file pages*/
			range_end = data->cacheseq[++idx] & MAX_TOUCHED_FILE_OFFSET;
			rpc.nr_to_read = range_end - rpc.offset;
			read_count = workingset_page_cache_range_read(&rpc);
			present_pages_cnt += rpc.nr_to_read - read_count;
			if (rpc.nr_to_read == 1)
				waste_cnt++;
			read_pages_cnt += read_count;
			move_lru_cnt += rpc.nr_adjusted;
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
			if (rpc.lastpage)
				lastpage = rpc.lastpage;
#endif /*CONFIG_HW_CGROUP_WORKINGSET_DEBUG*/
		} else {
			/*in the case, prereading single file page*/
			page = find_get_page(rpc.mapping, rpc.offset);
			if (page) {
				if (workingset_adjust_page_lru(page))
					move_lru_cnt++;
				put_page(page);
				present_pages_cnt++;
			} else {
				if (!workingset_page_cache_read(&rpc))
					read_pages_cnt++;
#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
				if (rpc.lastpage)
					lastpage = rpc.lastpage;
#endif /*CONFIG_HW_CGROUP_WORKINGSET_DEBUG*/
			}
		}
	}

	if (preread_major_page) {
		preread_major_page = false;
		goto try_next;
	}

#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
	if (lastpage)
		wait_on_page_locked(lastpage);
	time_end = ktime_get_ns();
#endif

	/*when many file pages are not present, the blkio count of main thread can be consider as the base blkio of prereading*/
	if (present_pages_cnt < ((data->page_sum * CACHE_MISSED_PERCENTAGE_THRESHOLD_FOR_BLKIO) / 100))
		to_preread->state |= E_RECORD_STATE_UPDATE_BASE_BLKIO;

#ifdef CONFIG_HW_CGROUP_WORKINGSET_DEBUG
	pr_info("%s: preread %s, filecount=%u, dealwith %u [major: %u waste: %u] pageseqs, %u pages, present: %u, moved: %u, readed: %u, consume %lu ms\n",
		__func__, to_preread->owner.name, data->file_cnt, data->pageseq_cnt, major_cnt, waste_cnt, data->page_sum, present_pages_cnt, move_lru_cnt, read_pages_cnt,
		(time_end-time_start)/1000000);
#else
	workingset_debug("%s: preread %s, filecount=%u, dealwith %u [major: %u waste: %u] pageseqs, %u pages, present: %u, moved: %u, readed: %u\n",
		__func__, to_preread->owner.name, data->file_cnt, data->pageseq_cnt, major_cnt, waste_cnt, data->page_sum, present_pages_cnt, move_lru_cnt, read_pages_cnt);
#endif
}

static void workingset_stop_preread_record_locked(struct s_workingset_record *to_preread)
{
       unsigned file_idx, idx;
       struct s_workingset_data *data;

       data = &to_preread->data;
       if (to_preread->preread_filpp) {
		for (file_idx = 0; file_idx < data->file_cnt; file_idx++) {
			if (to_preread->preread_filpp[file_idx])
				filp_close(to_preread->preread_filpp[file_idx], NULL);
		}
       }

	for (idx = 0; idx < FILP_PAGES_COUNT; idx++) {
		if (to_preread->filp_pages[idx]) {
			if (to_preread->preread_filpp) {
				vunmap(to_preread->preread_filpp);
				to_preread->preread_filpp = NULL;
			}
			__free_page(to_preread->filp_pages[idx]);
			to_preread->filp_pages[idx] = NULL;
		}
	}

	if (to_preread->preread_filpp) {
		free_page((unsigned long)to_preread->preread_filpp);
		to_preread->preread_filpp = NULL;
	}
}

static int workingset_collect_kworkthread(void *p)
{
	int ret;
	struct s_workingset_collector *collector;

	if (!p) {
		pr_err("%s: p is NULL!\n", __func__);
		return 0;
	}

	collector = (struct s_workingset_collector *)p;
	while (!kthread_should_stop()) {
		ret = wait_event_interruptible(
			collector->collect_wait,
			((collector->wait_flag == F_COLLECT_PENDING)
			|| (collector->wait_flag == F_RECORD_PENDING)));
		if (ret < 0)
			continue;

		workingset_collector_do_work(collector);
	}
	pr_err("%s: exit!\n", __func__);

	return 0;
}

void workingset_pagecache_record(struct file *file, pgoff_t start_offset, unsigned count)
{
	struct s_cachepage_info info, *target_space;
	struct task_struct *task = current;
	unsigned remain_space;

	if (unlikely(!file) || unlikely(start_offset > MAX_TOUCHED_FILE_OFFSET))
		return;

	if (unlikely(start_offset + count - 1 > MAX_TOUCHED_FILE_OFFSET))
		count = MAX_TOUCHED_FILE_OFFSET - start_offset + 1;

	info.filp = file;
	info.start_offset = (unsigned)start_offset;
	info.count = count;
	info.pid = task->pid;

	spin_lock(&workingset_collector->lock);
	if (workingset_collector->read_pos <= workingset_collector->write_pos)
		remain_space = COLLECTOR_CACHE_SIZE - workingset_collector->write_pos + workingset_collector->read_pos;
	else
		remain_space = workingset_collector->read_pos - workingset_collector->write_pos;

	/*when the circle buffer is almost full, we collect touched file page of main thread only*/
	if (remain_space < COLLECTOR_REMAIN_CACHE_LOW_WATER) {
		if ((task->pid != task->tgid) || (remain_space <= sizeof(struct s_cachepage_info))) {
			workingset_collector->discard_count++;
			spin_unlock(&workingset_collector->lock);
			return;
		}
	}

	target_space = (struct s_cachepage_info*)(workingset_collector->circle_buffer + workingset_collector->write_pos);
	*target_space = info;
	if (workingset_collector->write_pos + sizeof(struct s_cachepage_info) == COLLECTOR_CACHE_SIZE)
		workingset_collector->write_pos = 0;
	else
		workingset_collector->write_pos +=  sizeof(struct s_cachepage_info);
	atomic_long_inc(&file->f_count);
	spin_unlock(&workingset_collector->lock);

	if (waitqueue_active(&workingset_collector->collect_wait)) {
		workingset_collector->wait_flag = F_COLLECT_PENDING;
		wake_up_interruptible_all(&workingset_collector->collect_wait);
	}
}

static int __init cgroup_workingset_init(void)
{
	int ret = 0;
	struct page *page;

	if (COLLECTOR_CACHE_SIZE % sizeof(struct s_cachepage_info)) {
		pr_err("%s, COLLECTOR_CACHE_SIZE = %lu is not aligned with sizeof(struct s_cachepage_info) = %lu\n",
			__func__, COLLECTOR_CACHE_SIZE, sizeof(struct s_cachepage_info));
		ret = -EINVAL;
		goto out;
	}

	g_tfm = crypto_alloc_shash("crc32c", 0, 0);
	if (PTR_ERR_OR_ZERO(g_tfm)) {
		pr_err("%s, alloc crc32c cypto failed\n", __func__);
		goto out;
	}

	workingset_collector = (struct s_workingset_collector*)kzalloc(sizeof(struct s_workingset_collector), GFP_KERNEL);
	if (!workingset_collector) {
		pr_err("%s, create workingset_collector failed\n", __func__);
		goto create_collector_fail;
	}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
	page = alloc_pages_node(NUMA_NO_NODE, GFP_KERNEL,
						  COLLECTOR_CACHE_SIZE_ORDER);
#else
	page = alloc_kmem_pages_node(NUMA_NO_NODE, GFP_KERNEL,
						  COLLECTOR_CACHE_SIZE_ORDER);
#endif
	if (!page) {
		pr_err("%s, alloc workingset collector cache failed!\n", __func__);
		goto create_collector_cache_fail;
	}
	workingset_collector->circle_buffer = page_address(page);

	spin_lock_init(&workingset_collector->lock);
	init_waitqueue_head(&workingset_collector->collect_wait);

	workingset_collector->collector_thread = kthread_run(
			workingset_collect_kworkthread, workingset_collector, "workingset:collector");
	if (IS_ERR(workingset_collector->collector_thread)) {
		ret = PTR_ERR(workingset_collector->collector_thread);
		pr_err("%s: create the collector thread failed!\n", __func__);
		goto create_collector_thread_fail;
	}

	spin_lock_init(&g_workingset_list_lock);
	return 0;

create_collector_thread_fail:
#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
	__free_pages(virt_to_page(workingset_collector->circle_buffer), COLLECTOR_CACHE_SIZE_ORDER);
#else
	free_kmem_pages((unsigned long)workingset_collector->circle_buffer, COLLECTOR_CACHE_SIZE_ORDER);
#endif
	workingset_collector->circle_buffer = NULL;
create_collector_cache_fail:
	kfree(workingset_collector);
	workingset_collector = NULL;
create_collector_fail:
	crypto_free_shash(g_tfm);
	g_tfm = NULL;
out:
	return ret;
}

static void __exit cgroup_workingset_exit(void)
{
	kthread_stop(workingset_collector->collector_thread);
	workingset_collector->collector_thread = NULL;
#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
	__free_pages(virt_to_page(workingset_collector->circle_buffer), COLLECTOR_CACHE_SIZE_ORDER);
#else
	free_kmem_pages((unsigned long)workingset_collector->circle_buffer, COLLECTOR_CACHE_SIZE_ORDER);
#endif
	workingset_collector->circle_buffer = NULL;

	kfree(workingset_collector);
	crypto_free_shash(g_tfm);
	workingset_collector = NULL;
	g_tfm = NULL;
}

module_init(cgroup_workingset_init);
module_exit(cgroup_workingset_exit);
