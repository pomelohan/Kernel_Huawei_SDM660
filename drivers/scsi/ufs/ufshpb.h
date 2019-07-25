#ifndef _UFSHPB_H_
#define _UFSHPB_H_

#include <linux/spinlock.h>
#include <linux/circ_buf.h>
#include <linux/workqueue.h>

#define BLOCK 4096
#define SECTOR 512
#define CPAGE_BYTES (512 * 1024)
#define SECTORS_PER_BLOCK (BLOCK / SECTOR)
#define BITS_PER_DWORD (32)
#define MAX_MAP_REQ		16

enum ufshpb_state {
	HPB_PRESENT = 1,
	HPB_NOT_SUPPORTED = -1,
	HPB_FAILED = -2,
	HPB_NEED_INIT = 0,
	HPB_RESET = -3,
};

enum cache_block_state {
	CBLK_PINNED, CBLK_CACHED, CBLK_UNUSED,
};

enum cache_page_state {
	CPAGE_DIRTY, CPAGE_CLEAN, CPAGE_ISSUED, CPAGE_UNUSED,
};

struct ufshpb_func_desc {
	/*** Device Descriptor ***/
	/* 06h bNumberLU */
	int lu_cnt;
	/*** Geometry Descriptor ***/
	/* 0Dh dSegmentSize */
	unsigned int segment_size;
	/* 48h bHPBEntrySize (default 4B) */
	int hpb_entry_byte;
	/* 49h bHPBCacheBlockSize (default 1 = 4MB (same as segment size)) */
	int hpb_cblk_size;
	/* 4Ah bHPBNumberLU */
	int hpb_number_lu;
	/* 4Bh bNumHPBCachePage */
	int hpb_cpage_per_cblk;
	/* 4Ch bMaxHPBCacheBlock */
	int hpb_max_cblk;
};

struct ufshpb_lu_desc {
	/*** Unit Descriptor ****/
	/* 03h bLUEnable */
	int lu_enable;
	/* 0Ah bLogicalBlockSize. default 0x0C = 4KB */
	int lu_logblk_size;
	/* 0Bh qLogicalBlockCount. same as the read_capacity ret val. */
	u64 lu_logblk_cnt;

	/* 23h bHPBLuEnable */
	int lu_hpb_enable;
	/* 24h bUFSFLuFeature */
	int lu_hpb_feature;
	/* 25h bNumHPBCacheBlks */
	int lu_hpb_num_cblks;
	/* 26h bHPBPinnedCacheBlkStartOffset */
	int lu_hpb_pinned_start_offset;
	/* 27h bHPBPinnedCacheBlkEndOffset */
	int lu_hpb_pinned_end_offset;
};

#define HPB_RSP_INFO_NONE				0x00
#define HPB_RSP_INFO_HPB_UPDATED		0x01

#define HPB_RSP_TYPE_CHANGE_BLOCK		0x01
#define HPB_RSP_TYPE_READ_BUF_ISSUE		0x02
#define HPB_RSP_TYPE_HPB_ENTRY_UPDATE	0x03

struct ufshpb_rsp_info {
	u8 hpb_info[8];
	u8 hpb_field[13];
};

struct ufshpb_tdata {
	unsigned long long *ppn_table;
	unsigned int *ppn_dirty;

	struct list_head list_table;
};

struct ufshpb_cpage {
	struct ufshpb_tdata *td;
	enum cache_page_state cpage_state;
	int cblk;
	int cpage;

	struct list_head list_cpage;
};

struct ufshpb_cblock {
	struct ufshpb_cpage *cpage_tbl;
	enum cache_block_state cblk_state;
	int cblk;
	int cpage_count;

	struct list_head list_cblock;
};

struct ufshpb_map_req {
	struct ufshpb_lu *hpb;
	struct request req;
	void (*end_io)(struct request *rq, int err);
	void *end_io_data;
	void *p;
	int cblk;
	int cpage;
	int lun;
};

struct ufshpb_lu {
	struct ufshpb_cblock *cblk_tbl;

	struct list_head lh_free_table;
	struct list_head lh_cpage_req;
	int debug_free_table;

	struct ufshpb_map_req map_req[MAX_MAP_REQ];
	int map_idx;

	bool lu_hpb_enable;

	struct work_struct ufshpb_work;

	int cpages_per_lu;
	int cblks_per_lu;

	int entries_per_cpage;
	int entries_per_cpage_shift;
	int entries_per_cpage_mask;

	int entries_per_cblk;
	int entries_per_cblk_shift;
	int entries_per_cblk_mask;
	int cpages_per_cblk;

	int dwords_per_cpage;
	int cpage_bytes;

	/* for debug constant variables */
	int entries_per_lu;

	int lun;

	struct ufs_hba *hba;

	spinlock_t hpb_lock;

	struct kobject kobj;
	struct mutex sysfs_lock;
	struct ufshpb_sysfs_entry *sysfs_entries;

	/* for debug */
	bool force_disable;
	bool force_map_req_disable;
	bool debug;
	atomic64_t hit;
	atomic64_t miss;
	atomic64_t map_req_cnt;
	atomic64_t cblk_add;
	atomic64_t cblk_evict;
};

struct ufshpb_sysfs_entry {
	struct attribute    attr;
	ssize_t (*show)(struct ufshpb_lu *hpb, char *buf);
	ssize_t (*store)(struct ufshpb_lu *hpb, const char *, size_t);
};

struct ufshcd_lrb;

void ufshpb_prep_fn(struct ufs_hba *hba, struct ufshcd_lrb *lrbp);
void ufshpb_rsp_hpb_info(struct ufs_hba *hba, struct ufshcd_lrb *lrbp);
int ufshpb_init(struct ufs_hba *hba);
void ufshpb_release(struct ufs_hba *hba, int state);
void ufshpb_probe(struct ufs_hba *hba);
#endif /* End of Header */
