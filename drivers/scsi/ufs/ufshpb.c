#include <linux/slab.h>
#include <linux/blkdev.h>
#include <scsi/scsi.h>
#include <linux/sysfs.h>
#include <linux/blktrace_api.h>

#include "ufs.h"
#include "ufshcd.h"
#include "ufshpb.h"

/*
 * UFSHPB DEBUG
 * */
#define debugk(hpb, fmt, ...) do {\
	if (hpb->debug)\
		printk(fmt, ##__VA_ARGS__);\
	} while (0)
#define TMSG(hpb, ...) do {\
	if (hpb->hba->sdev_ufs_lu[hpb->lun] &&\
			hpb->hba->sdev_ufs_lu[hpb->lun]->request_queue)\
		blk_add_trace_msg(\
				hpb->hba->sdev_ufs_lu[hpb->lun]->request_queue,\
				##__VA_ARGS__);\
	} while (0)

/*
 * debug variables
 */
int alloc_td;

/*
 * define global constants
 */
static int sects_per_blk_shift;
static int bits_per_dword_shift;
static int bits_per_dword_mask;
static int bits_per_byte_shift;

static int ufshpb_create_sysfs(struct ufs_hba *hba,
		struct ufshpb_lu *hpb);
static void ufshpb_error_handler(struct work_struct *work);

static inline void ufshpb_get_bit_offset(
		struct ufshpb_lu *hpb, int cpage_offset,
		int *dword, int *offset)
{
	*dword = cpage_offset >> bits_per_dword_shift;
	*offset = cpage_offset & bits_per_dword_mask;
}

/* called with hpb_lock (irq) */
static bool ufshpb_is_page_dirty(struct ufshpb_lu *hpb,
		struct ufshpb_cpage *cp, int cpage_offset)
{
	bool is_dirty;
	unsigned int bit_dword, bit_offset;

	ufshpb_get_bit_offset(hpb, cpage_offset,
			&bit_dword, &bit_offset);

	if (!cp->td->ppn_dirty)
		return false;

	is_dirty = cp->td->ppn_dirty[bit_dword] &
		(1 << bit_offset) ? true : false;

	return is_dirty;
}

static void ufshpb_ppn_prep(struct ufshpb_lu *hpb,
		struct ufshcd_lrb *lrbp, unsigned long long ppn)
{
	unsigned char cmd[16] = { 0 };
	unsigned int transfer_len;

	transfer_len = (lrbp->cmd->cmnd[7] << 8) |
		(lrbp->cmd->cmnd[8] & 0xff);

	cmd[0] = READ_16;
	cmd[2] = lrbp->cmd->cmnd[2];
	cmd[3] = lrbp->cmd->cmnd[3];
	cmd[4] = lrbp->cmd->cmnd[4];
	cmd[5] = lrbp->cmd->cmnd[5];
	cmd[6] = (unsigned long long) (ppn >> 56) & 0xff;
	cmd[7] = (unsigned long long) (ppn >> 48) & 0xff;
	cmd[8] = (unsigned long long) (ppn >> 40) & 0xff;
	cmd[9] = (unsigned long long) (ppn >> 32) & 0xff;
	cmd[10] = (unsigned long long) (ppn >> 24) & 0xff;
	cmd[11] = (unsigned long long) (ppn >> 16) & 0xff;
	cmd[12] = (unsigned long long) (ppn >> 8) & 0xff;
	cmd[13] = (unsigned long long) ppn & 0xff;
	cmd[14] = 0x11;
	cmd[15] = transfer_len & 0xff;

	memcpy(lrbp->cmd->cmnd, cmd, MAX_CDB_SIZE);
	memcpy(lrbp->ucd_req_ptr->sc.cdb, cmd, MAX_CDB_SIZE);
}

/* called with hpb_lock (irq) */
static inline void ufshpb_set_dirty_bits(struct ufshpb_lu *hpb,
		struct ufshpb_cblock *cb, struct ufshpb_cpage *cp,
		int dword, int offset, unsigned int count)
{
	const unsigned long mask = ((1UL << count) - 1) & 0xffffffff;

	if (cb->cblk_state == CBLK_UNUSED)
		return;

	BUG_ON(!cp->td);
	cp->td->ppn_dirty[dword] |= (mask << offset);
}

static void ufshpb_set_dirty(struct ufshpb_lu *hpb,
		struct ufshcd_lrb *lrbp, int cblk, int cpage, int cpage_offset)
{
	struct ufshpb_cblock *cb;
	struct ufshpb_cpage *cp;
	unsigned long flags;
	int count;
	int bit_count, bit_dword, bit_offset;

	count = blk_rq_sectors(lrbp->cmd->request) >> sects_per_blk_shift;
	ufshpb_get_bit_offset(hpb, cpage_offset,
			&bit_dword, &bit_offset);

	do {
		bit_count = min(count, BITS_PER_DWORD - bit_offset);

		cb = hpb->cblk_tbl + cblk;
		cp = cb->cpage_tbl + cpage;

		spin_lock_irqsave(&hpb->hpb_lock, flags);
		ufshpb_set_dirty_bits(hpb, cb, cp,
				bit_dword, bit_offset, bit_count);
		spin_unlock_irqrestore(&hpb->hpb_lock, flags);

		bit_offset = 0;
		bit_dword++;

		if (bit_dword == hpb->dwords_per_cpage) {
			bit_dword = 0;
			cpage++;

			if (cpage == hpb->cpages_per_cblk) {
				cpage = 0;
				cblk++;
			}
		}

		count -= bit_count;
	} while (count);

	BUG_ON(count < 0);
}

static inline bool ufshpb_is_read_lrbp(struct ufshcd_lrb *lrbp)
{
	if (lrbp->cmd->cmnd[0] == READ_10 || lrbp->cmd->cmnd[0] == READ_16)
		return true;

	return false;
}

static inline bool ufshpb_is_write_discard_lrbp(struct ufshcd_lrb *lrbp)
{
	if (lrbp->cmd->cmnd[0] == WRITE_10 || lrbp->cmd->cmnd[0] == WRITE_16
			|| lrbp->cmd->cmnd[0] == UNMAP)
		return true;

	return false;
}

static inline void ufshpb_get_pos_from_lpn(struct ufshpb_lu *hpb,
		unsigned int lpn, int *cblk, int *cpage,
		int *offset)
{
	int cblk_offset;

	*cblk = lpn >> hpb->entries_per_cblk_shift;
	cblk_offset = lpn & hpb->entries_per_cblk_mask;
	*cpage = cblk_offset >> hpb->entries_per_cpage_shift;
	*offset = cblk_offset & hpb->entries_per_cpage_mask;
}

void ufshpb_prep_fn(struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	struct ufshpb_lu *hpb;
	struct ufshpb_cblock *cb;
	struct ufshpb_cpage *cp;
	unsigned long flags;
	unsigned int lpn;
	unsigned long long ppn = 0;
	int cblk, cpage, cpage_offset;

	/* WKLU could not be HPB-LU */
	if (lrbp->lun >= UFS_UPIU_MAX_GENERAL_LUN)
		return;

	hpb = hba->ufshpb_lup[lrbp->lun];
	if (!hpb || !hpb->lu_hpb_enable) {
		if (ufshpb_is_read_lrbp(lrbp))
			goto read_10;
		return;
	}

	if (hpb->force_disable) {
		if (ufshpb_is_read_lrbp(lrbp))
			goto read_10;
		return;
	}

	lpn = blk_rq_pos(lrbp->cmd->request) / SECTORS_PER_BLOCK;
	ufshpb_get_pos_from_lpn(hpb, lpn, &cblk,
			&cpage, &cpage_offset);
	cb = hpb->cblk_tbl + cblk;

	if (ufshpb_is_write_discard_lrbp(lrbp)) {
		if (cb->cblk_state == CBLK_UNUSED)
			return;
		ufshpb_set_dirty(hpb, lrbp, cblk, cpage, cpage_offset);
		return;
	}

	if (!ufshpb_is_read_lrbp(lrbp))
		return;

	if (blk_rq_sectors(lrbp->cmd->request) != SECTORS_PER_BLOCK) {
		blk_add_trace_msg(
				hpb->hba->sdev_ufs_lu[hpb->lun]->request_queue,
				"%llu + %u READ_10 many_blocks %d - %d",
				(unsigned long long) blk_rq_pos(lrbp->cmd->request),
				(unsigned int) blk_rq_sectors(lrbp->cmd->request), cblk, cpage);
		TMSG(hpb, "%llu + %u READ_10 many_blocks %d - %d",
				(unsigned long long) blk_rq_pos(lrbp->cmd->request),
				(unsigned int) blk_rq_sectors(lrbp->cmd->request), cblk, cpage);
		return;
	}

	cp = cb->cpage_tbl + cpage;

	spin_lock_irqsave(&hpb->hpb_lock, flags);
	if (cb->cblk_state == CBLK_UNUSED ||
			cp->cpage_state != CPAGE_CLEAN) {
		spin_unlock_irqrestore(&hpb->hpb_lock, flags);

		if (cb->cblk_state == CBLK_UNUSED)
			TMSG(hpb, "%llu + %u READ_10 CBLK_UNUSED %d - %d",
					(unsigned long long) blk_rq_pos(lrbp->cmd->request),
					(unsigned int) blk_rq_sectors(lrbp->cmd->request), cblk, cpage);
		else if (cp->cpage_state == CPAGE_DIRTY
				|| cp->cpage_state == CPAGE_ISSUED)
			TMSG(hpb, "%llu + %u READ_10 CPAGE_DIRTY %d - %d",
					(unsigned long long) blk_rq_pos(lrbp->cmd->request),
					(unsigned int) blk_rq_sectors(lrbp->cmd->request), cblk, cpage);
		else
			TMSG(hpb, "%llu + %u READ_10 ( %d %d ) %d - %d",
					(unsigned long long) blk_rq_pos(lrbp->cmd->request),
					(unsigned int) blk_rq_sectors(lrbp->cmd->request),
					cb->cblk_state, cp->cpage_state, cblk, cpage);
		atomic64_inc(&hpb->miss);
		return;
	}

	if (ufshpb_is_page_dirty(hpb, cp, cpage_offset)) {
		spin_unlock_irqrestore(&hpb->hpb_lock, flags);
		TMSG(hpb, "%llu + %u READ_10 page_dirty %d - %d",
				(unsigned long long) blk_rq_pos(lrbp->cmd->request),
				(unsigned int) blk_rq_sectors(lrbp->cmd->request), cblk, cpage);
		atomic64_inc(&hpb->miss);
		return;
	}

	ppn = cp->td->ppn_table[cpage_offset];
	spin_unlock_irqrestore(&hpb->hpb_lock, flags);

	ufshpb_ppn_prep(hpb, lrbp, ppn);
	TMSG(hpb, "%llu + %u READ_16 + %llx %d - %d",
			(unsigned long long) blk_rq_pos(lrbp->cmd->request),
			(unsigned int) blk_rq_sectors(lrbp->cmd->request), ppn, cblk, cpage);
	atomic64_inc(&hpb->hit);
	return;
read_10:
	if (!hpb || !lrbp)
		return;
	TMSG(hpb, "%llu + %u READ_10",
			(unsigned long long) blk_rq_pos(lrbp->cmd->request),
			(unsigned int) blk_rq_sectors(lrbp->cmd->request));
	atomic64_inc(&hpb->miss);
	return;
}

static inline void ufshpb_clear_dirty_bits(struct ufshpb_cpage *cache_page,
		int dword, int offset, int count)
{
	const unsigned long mask = ((1UL << count) - 1) & 0xffffffff;

	cache_page->td->ppn_dirty[dword] &= (~mask) << offset;
}

static int ufshpb_update_hpb_entries(struct ufshpb_lu *hpb,
		unsigned char *field, struct ufshcd_lrb *lrbp)
{
	struct ufshpb_cpage *cp;
	unsigned int lpn;
	unsigned long long ppn;
	int cblk, cpage, cpage_offset;
	int bit_dword, bit_offset;

	lpn = *(unsigned int *)(field + 0);
	ppn = *(unsigned long long *)(field + 4);

	ufshpb_get_pos_from_lpn(hpb, lpn, &cblk,
			&cpage, &cpage_offset);
	ufshpb_get_bit_offset(hpb, cpage_offset,
			&bit_dword, &bit_offset);

	debugk(hpb, "%s:%d UPDATE_ENTRY %u - 0x%.16llX %d - %d\n",
			__func__, __LINE__, lpn, ppn, cblk, cpage);
	if (lpn > hpb->entries_per_lu || cblk > hpb->cblks_per_lu) {
		debugk(hpb, "%s:%d get invalid lpn\n", __func__, __LINE__);
		return -ENOMEM;
	}

	/* if cblk state is unused, its cblk has been evicted and
	 * driver can ignore the update-list */
	spin_lock(&hpb->hpb_lock);
	if (hpb->cblk_tbl[cblk].cblk_state == CBLK_UNUSED) {
		spin_unlock(&hpb->hpb_lock);
		return 0;
	}

	cp = hpb->cblk_tbl[cblk].cpage_tbl + cpage;

	cp->td->ppn_table[cpage_offset] = ppn;
	ufshpb_clear_dirty_bits(cp, bit_dword, bit_offset, 1);
	spin_unlock(&hpb->hpb_lock);

	TMSG(hpb, "%s:%d HPB-UDPATE-ENTRY lpn %u ppn %llx",
			__func__, __LINE__, lpn, ppn);

	return 0;
}

static void ufshpb_clean_cache_page(
		struct ufshpb_lu *hpb, struct ufshpb_cpage *cp)
{
	unsigned long flags;
	struct ufshpb_cblock *cb;

	cb = hpb->cblk_tbl + cp->cblk;

	/* if td is null, cache block had been evicted out */
	spin_lock_irqsave(&hpb->hpb_lock, flags);
	if (cb->cblk_state == CBLK_UNUSED || !cp->td) {
		spin_unlock_irqrestore(&hpb->hpb_lock, flags);
		debugk(hpb, "%s:%d %d - %d evicted\n", __func__, __LINE__,
				cp->cblk, cp->cpage);
		return;
	}

	memset(cp->td->ppn_dirty, 0x00,
			hpb->entries_per_cpage >> bits_per_byte_shift);
	cp->cpage_state = CPAGE_CLEAN;
	spin_unlock_irqrestore(&hpb->hpb_lock, flags);
}

static void ufshpb_map_req_compl_fn(struct request *req, int error)
{
	struct ufshpb_map_req *map_req =
		(struct ufshpb_map_req *) req->end_io_data;
	struct ufs_hba *hba;
	struct ufshpb_lu *hpb;

	hpb = map_req->hpb;
	hba = hpb->hba;

	debugk(hpb, "%s:%d READ_BUFFER COMPL %d - %d table %p map[%d] %llx [%d] %llx\n",
			__func__, __LINE__, map_req->cblk, map_req->cpage,
			map_req->p, 0, ((unsigned long long*)map_req->p)[0],
			hpb->entries_per_cpage,
			((unsigned long long*)map_req->p)[hpb->entries_per_cpage]);
	TMSG(hpb, "%s:%d READ_BUFFER COMPL %d - %d table %p map[%d] %llx [%d] %llx",
			__func__, __LINE__, map_req->cblk, map_req->cpage,
			map_req->p, 0, ((unsigned long long*)map_req->p)[0],
			hpb->entries_per_cpage,
			((unsigned long long*)map_req->p)[hpb->entries_per_cpage]);

	ufshpb_clean_cache_page(hpb,
			hpb->cblk_tbl[map_req->cblk].cpage_tbl + map_req->cpage);
}

static inline void ufshpb_set_read_buf_cmd(unsigned char *cmd,
		int cblk, int cpage, int length)
{
	cmd[0] = READ_BUFFER;
	cmd[1] = 0x02;
	cmd[2] = 0x00;
	cmd[3] = (unsigned char) (cblk >> 8) & 0xff;
	cmd[4] = cblk & 0xff;
	cmd[5] = cpage;

	cmd[6] = (unsigned char) (length >> 16) & 0xFF;
	cmd[7] = (unsigned char) (length >> 8) & 0xFF;
	cmd[8] = (unsigned char) (length) & 0xFF;
}

static void ufshpb_map_req_init_issue(struct ufshpb_lu *hpb,
		struct request_queue *q, struct ufshpb_map_req *map_req)
{
	struct request *req;
	unsigned char cmd[16] = { 0 };
	int length = 512 * 1024;

	ufshpb_set_read_buf_cmd(cmd, map_req->cblk, map_req->cpage, length);

	req = &map_req->req;

	blk_rq_init(q, req);
	blk_rq_map_kern(q, req, map_req->p, length, GFP_ATOMIC);

	req->cmd_len = COMMAND_SIZE(cmd[0]);
	memcpy(req->cmd, cmd, req->cmd_len);

	req->cmd_type = REQ_TYPE_BLOCK_PC;
	req->cmd_flags = READ | REQ_SOFTBARRIER | REQ_QUIET | REQ_PREEMPT;
	req->retries = 3;
	req->timeout = msecs_to_jiffies(30000);
	req->end_io = ufshpb_map_req_compl_fn;
	req->end_io_data = (void *)map_req;

	debugk(hpb, "%s:%d READ_BUFFER ISSUE %d - %d table %p map[%d] %llx [%d] %llx\n",
			__func__, __LINE__, map_req->cblk, map_req->cpage,
			map_req->p, 0, ((unsigned long long*)map_req->p)[0],
			hpb->entries_per_cpage,
			((unsigned long long*)map_req->p)[hpb->entries_per_cpage]);
	TMSG(hpb, "%s:%d READ_BUFFER ISSUE %d - %d table %p map[%d] %llx [%d] %llx",
			__func__, __LINE__, map_req->cblk, map_req->cpage,
			map_req->p, 0, ((unsigned long long*)map_req->p)[0],
			hpb->entries_per_cpage,
			((unsigned long long*)map_req->p)[hpb->entries_per_cpage]);

	/* this sequence already has spin_lock_irqsave() */
	list_add(&req->queuelist, &q->queue_head);

	atomic64_inc(&hpb->map_req_cnt);
}

/* routine : softirq (block) */
static void ufshpb_map_req_cb_fn(struct request *req, int error)
{
	struct ufshpb_map_req *map_req;
	struct ufshpb_lu *hpb;
	struct ufs_hba *hba;

	map_req = (struct ufshpb_map_req *)req->end_io_data;
	hpb = map_req->hpb;
	hba = hpb->hba;

	if (map_req->end_io) {
		req->end_io_data= map_req->end_io_data;
		map_req->end_io(req, error);
	} else {
		if (blk_bidi_rq(req))
			__blk_put_request(req->next_rq->q, req->next_rq);
		__blk_put_request(req->q, req);
	}

	ufshpb_map_req_init_issue(hpb,
			hpb->hba->sdev_ufs_lu[hpb->lun]->request_queue, map_req);
}

static void ufshpb_set_map_req_fn(struct ufshpb_lu *hpb,
		struct ufshcd_lrb *lrbp, int cblk, int cpage, void *table)
{
	struct ufshpb_map_req *map_req;
	struct request *req;

	req = lrbp->cmd->request;

	spin_lock(&hpb->hpb_lock);
	map_req = hpb->map_req + hpb->map_idx;
	hpb->map_idx = (hpb->map_idx + 1) % MAX_MAP_REQ;
	spin_unlock(&hpb->hpb_lock);

	map_req->cblk = cblk;
	map_req->cpage = cpage;
	map_req->p = table;
	map_req->lun = lrbp->lun;

	if (req->end_io)
		map_req->end_io = req->end_io;
	else
		map_req->end_io = NULL;

	if (req->end_io_data)
		map_req->end_io_data = req->end_io_data;

	req->end_io = ufshpb_map_req_cb_fn;
	req->end_io_data = map_req;
}

static struct ufshpb_tdata *ufshpb_get_table_data(
		struct ufshpb_lu *hpb, int *err)
{
	struct ufshpb_tdata *td;

	td = list_first_entry_or_null(&hpb->lh_free_table,
			struct ufshpb_tdata, list_table);
	if (td) {
		list_del_init(&td->list_table);
		hpb->debug_free_table--;
		return td;
	}
	*err = -ENOMEM;
	return NULL;
}

static inline int ufshpb_add_cblk(struct ufshpb_lu *hpb, int cblk)
{
	struct ufshpb_cblock *cb;
	int cpage;
	int err = 0;

	cb = hpb->cblk_tbl + cblk;

	debugk(hpb, "%s:%d E->CACHED CBLK: %d \n", __func__, __LINE__, cblk);
	TMSG(hpb, "%s:%d E->CACHED CBLK: %d", __func__, __LINE__, cblk);

	spin_lock(&hpb->hpb_lock);
	for (cpage = 0 ; cpage < cb->cpage_count ; cpage++) {
		struct ufshpb_cpage *cp;

		cp = cb->cpage_tbl + cpage;

		cp->td = ufshpb_get_table_data(hpb, &err);
		if (!cp->td) {
			debugk(hpb, "%s:%d get td failed. err %d cpage %d free_table %d\n",
					__func__, __LINE__, err, cpage, hpb->debug_free_table);
			goto out;
		}

		cp->cpage_state = CPAGE_DIRTY;
	}
	cb->cblk_state = CBLK_CACHED;
out:
	spin_unlock(&hpb->hpb_lock);
	return err;
}

static inline void ufshpb_put_table_data(
		struct ufshpb_lu *hpb, struct ufshpb_tdata *td)
{
	list_add(&td->list_table, &hpb->lh_free_table);
	hpb->debug_free_table++;
}

static inline void ufshpb_purge_cache_page(struct ufshpb_lu *hpb,
		struct ufshpb_cpage *cp, int state)
{
	if (state == CPAGE_UNUSED) {
		ufshpb_put_table_data(hpb, cp->td);
		cp->td = NULL;
	}

	cp->cpage_state = state;
}

static inline void ufshpb_evict_cblk(struct ufshpb_lu *hpb, int cblk)
{
	struct ufshpb_cblock *cb;
	struct ufshpb_cpage *cp;
	int cpage;

	debugk(hpb, "%s:%d C->EVICT CBLK: %d\n", __func__, __LINE__, cblk);
	TMSG(hpb, "%s:%d C->EVICT CBLK: %d", __func__, __LINE__, cblk);

	cb = hpb->cblk_tbl + cblk;

	spin_lock(&hpb->hpb_lock);
	cb->cblk_state = CBLK_UNUSED;
	for (cpage = 0 ; cpage < cb->cpage_count ; cpage++) {
		cp = cb->cpage_tbl + cpage;

		ufshpb_purge_cache_page(hpb, cp, CPAGE_UNUSED);
	}

	spin_unlock(&hpb->hpb_lock);
}

static inline int ufshpb_test_list_bits(int nr,
		const volatile unsigned long long *addr)
{
#define BIT_LONGLONG(nr) ((nr) / BITS_PER_LONG_LONG)
	return 1UL & (addr[BIT_LONGLONG(nr)] >> (nr & (BITS_PER_LONG_LONG - 1)));
}

static int ufshpb_evict_load_cblk(struct ufshpb_lu *hpb,
		unsigned long long list_bits)
{
	struct list_head lh_evict, lh_add;
	struct ufshpb_cblock *cb;
	int cblk, ret;
	bool valid;

	INIT_LIST_HEAD(&lh_evict);
	INIT_LIST_HEAD(&lh_add);

	for (cblk = 0 ; cblk < hpb->cblks_per_lu ; cblk++) {
		struct ufshpb_cblock *cb;
		cb = hpb->cblk_tbl + cblk;

		valid = ufshpb_test_list_bits(cblk, &list_bits);
		if (!valid && (cb->cblk_state == CBLK_CACHED)) {
			list_add_tail(&cb->list_cblock, &lh_evict);
		} else if (valid && (cb->cblk_state == CBLK_UNUSED)) {
			list_add_tail(&cb->list_cblock, &lh_add);
		} else if (!valid && (cb->cblk_state == CBLK_PINNED)) {
			/*
			 * Pinned cache-block should not drop-out.
			 * But if so, it would treat error as critical,
			 * and it will run ufshpb_eh_work
			 */
			dev_warn(hpb->hba->dev,
					"UFSHPB pinned cache-block drop-out error\n");
			goto error;
		}
	}

	/* we first should reclaim table_data from evicted-cblk,
	 * and then, alloc table_data to cached-cblk */
	while (!list_empty(&lh_evict)) {
		cb = list_first_entry(&lh_evict, struct ufshpb_cblock, list_cblock);
		list_del_init(&cb->list_cblock);
		atomic64_inc(&hpb->cblk_evict);
		ufshpb_evict_cblk(hpb, cb->cblk);
	}

	/* alloc table_data to cached-cblk */
	while (!list_empty(&lh_add)) {
		cb = list_first_entry(&lh_add, struct ufshpb_cblock, list_cblock);
		list_del_init(&cb->list_cblock);
		atomic64_inc(&hpb->cblk_add);
		ret = ufshpb_add_cblk(hpb, cb->cblk);
		if (ret) {
		dev_warn(hpb->hba->dev,
			"UFSHPB memory allocation failed\n");
		goto error;
		}
	}

	return 0;
error:
	return -ENOMEM;
}

static void ufshpb_change_block_list(struct ufshpb_lu *hpb,
		unsigned char *field)
{
	unsigned long long list_bits;
	int ret;

	list_bits = *(unsigned long *)field;
	debugk(hpb, "%s:%d CBLK-List Bits: %llx\n",
			__func__, __LINE__, list_bits);
	TMSG(hpb, "%s:%d CBLK-LIST %llx", __func__, __LINE__, list_bits);

	ret = ufshpb_evict_load_cblk(hpb, list_bits);
	if (ret) {
		debugk(hpb, "%s:%d evict/load failed. ret %d\n",
				__func__, __LINE__, ret);
		goto wakeup_ee_worker;
	}

	return;
wakeup_ee_worker:
	hpb->hba->ufshpb_state = HPB_FAILED;
	schedule_work(&hpb->hba->ufshpb_eh_work);
	return;
}

static inline struct ufshpb_rsp_info *ufshpb_get_hpb_rsp(
		struct ufshcd_lrb *lrbp)
{
	return (struct ufshpb_rsp_info *)&lrbp->ucd_rsp_ptr->sr.sense_data_len;
}

static inline int ufshpb_get_lu_number(struct ufshpb_rsp_info *rsp_info)
{
	return rsp_info->hpb_info[2];
}

static void ufshpb_rsp_map_cmd_req(struct ufshpb_lu *hpb,
		struct ufshcd_lrb *lrbp, unsigned char *field)
{
	struct ufshpb_cpage *cp;
	unsigned long long list_bits;
	int cblk, cpage;
	int i;
	int ret;

	list_bits = *(unsigned long long *)(field + 4);
	cblk = (field[1] << 8) | field[0];
	cpage = field[2];

	debugk(hpb, "%s:%d %d - %d will issue map-req, CBLK-LIST %llx\n",
			__func__, __LINE__, cblk, cpage, list_bits);

	ret = ufshpb_evict_load_cblk(hpb, list_bits);
	if (ret) {
		debugk(hpb, "%s:%d cblk evict/load failed. ret %d\n",
				__func__, __LINE__, ret);
		goto wakeup_ee_worker;
	}

	/* debugging */
	if (hpb->cblk_tbl[cblk].cblk_state == CBLK_UNUSED) {
		printk("%s:%d bit %.16lx now %d\n", __func__, __LINE__,
				hpb->hba->outstanding_reqs, lrbp->task_tag);
		for (i = 0 ; i < 16 ; i++) {
			int lun;
			struct ufshpb_rsp_info *rsp_info;
			struct ufshcd_lrb *lrbp;
			lrbp = hpb->hba->lrb + i;
			rsp_info = ufshpb_get_hpb_rsp(lrbp);

			lun = ufshpb_get_lu_number(rsp_info);

			debugk(hpb, "%s:%d(%d)(%d) HPB-Info Noti: %d Type: %d LUN: %d Seg-Len %d\n",
					__func__, __LINE__, i, !(!(hpb->hba->outstanding_reqs & (0x1 << i))),
					rsp_info->hpb_info[0], rsp_info->hpb_info[1], lun,
					be32_to_cpu(lrbp->ucd_rsp_ptr->header.dword_2)
					& MASK_RSP_UPIU_DATA_SEG_LEN);
		}

		return;
	}

	cp = hpb->cblk_tbl[cblk].cpage_tbl + cpage;

	/* if cpage_state set CPAGE_ISSUED,
	 * cache_page has already been added to list,
	 * so it just ends function.
	 * */
	if (cp->cpage_state == CPAGE_ISSUED)
		return;

	cp->cpage_state = CPAGE_ISSUED;
	if (hpb->force_map_req_disable) {
		debugk(hpb, "%s:%d map disable - return\n", __func__, __LINE__);
		return;
	}

	ufshpb_set_map_req_fn(hpb, lrbp, cblk, cpage, cp->td->ppn_table);

	return;
wakeup_ee_worker:
	hpb->hba->ufshpb_state = HPB_FAILED;
	schedule_work(&hpb->hba->ufshpb_eh_work);
	return;
}

/* routine : isr (ufs) */
void ufshpb_rsp_hpb_info(struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	struct ufshpb_lu *hpb;
	struct ufshpb_rsp_info *rsp_info;
	int lun;
	int data_seg_len;
	int err = 0;

	data_seg_len = be32_to_cpu(lrbp->ucd_rsp_ptr->header.dword_2)
		& MASK_RSP_UPIU_DATA_SEG_LEN;
	if (!data_seg_len)
		return;

	rsp_info = ufshpb_get_hpb_rsp(lrbp);
	if (rsp_info->hpb_info[0] != HPB_RSP_INFO_HPB_UPDATED)
		return;

	lun = ufshpb_get_lu_number(rsp_info);
	hpb = hba->ufshpb_lup[lun];

	debugk(hpb, "%s:%d HPB-Info Noti: %d Type: %d LUN: %d Seg-Len %d\n",
			__func__, __LINE__,
			rsp_info->hpb_info[0], rsp_info->hpb_info[1], lun,
			be32_to_cpu(lrbp->ucd_rsp_ptr->header.dword_2)
			& MASK_RSP_UPIU_DATA_SEG_LEN);
	TMSG(hpb, "%s:%d HPB-Info Noti: %d Type: %d LUN: %d Seg-Len %d",
			__func__, __LINE__,
			rsp_info->hpb_info[0], rsp_info->hpb_info[1], lun,
			be32_to_cpu(lrbp->ucd_rsp_ptr->header.dword_2)
			& MASK_RSP_UPIU_DATA_SEG_LEN);

	if (!hpb->lu_hpb_enable) {
		dev_warn(hba->dev, "UFSHPB(%s) LU(%d) not HPB-LU\n", __func__, lun);
		return;
	}

	switch (rsp_info->hpb_info[1]) {
		case HPB_RSP_TYPE_CHANGE_BLOCK:
			WARN_ON(data_seg_len != 0x10);
			ufshpb_change_block_list(hpb, rsp_info->hpb_field);
			break;
		case HPB_RSP_TYPE_READ_BUF_ISSUE:
			WARN_ON(data_seg_len != 0x14);
			ufshpb_rsp_map_cmd_req(hpb, lrbp, rsp_info->hpb_field);
			break;
		case HPB_RSP_TYPE_HPB_ENTRY_UPDATE:
			WARN_ON(data_seg_len != 0x14);
			err = ufshpb_update_hpb_entries(hpb, rsp_info->hpb_field, lrbp);
			if (err)
				goto err_out;
			break;
		default:
			break;
	}

	return;
err_out:
	debugk(hpb, "UFSHPB error (%d) %s:%d run ufshpb_eh_work\n", err,
			__func__, __LINE__);
	hpb->hba->ufshpb_state = HPB_FAILED;
	schedule_work(&hpb->hba->ufshpb_eh_work);
}

static inline void ufshpb_add_cpage_to_req_list(struct ufshpb_lu *hpb,
		struct ufshpb_cpage *cp)
{
	list_add_tail(&cp->list_cpage, &hpb->lh_cpage_req);
	cp->cpage_state = CPAGE_ISSUED;
}

static int ufshpb_execute_req(struct ufshpb_lu *hpb,
		unsigned char *cmd, void *buf, int length)
{
	unsigned long flags;
	struct scsi_sense_hdr sshdr;
	struct scsi_device *sdp;
	struct ufs_hba *hba;
	int ret = 0;
	int i, zero = 0, ff = 0;

	hba = hpb->hba;

	if (!hba->sdev_ufs_lu[hpb->lun]) {
		dev_warn(hba->dev, "(%s) UFSHPB cannot find scsi_device\n", __func__);
		return -ENODEV;
	}

	spin_lock_irqsave(hba->host->host_lock, flags);
	sdp = hba->sdev_ufs_lu[hpb->lun];
	if (!sdp) {
		ret = -ENODEV;
		return ret;
	}

	ret = scsi_device_get(sdp);
	if (!ret && !scsi_device_online(sdp)) {
		spin_unlock_irqrestore(hba->host->host_lock, flags);
		ret = -ENODEV;
		scsi_device_put(sdp);
		return ret;
	}
	spin_unlock_irqrestore(hba->host->host_lock, flags);

	// TODO: scsi status에 따라서 retry 수행
	ret = scsi_execute_req_flags(sdp, cmd, DMA_FROM_DEVICE,
			buf, length, &sshdr,
			msecs_to_jiffies(30000), 3, NULL, 0);
	scsi_device_put(sdp);

	for (i = 0 ; i < hpb->entries_per_cpage ; i++) {
		if (((unsigned int *)buf)[i] == 0)
			zero++;
		else if (((unsigned int *)buf)[i] == 0xffffffffffffffffull)
			ff++;
	}

	return ret;
}

static int ufshpb_issue_map_req_from_list(struct ufshpb_lu *hpb)
{
	struct ufshpb_cpage *cp, *next_cp;
	unsigned long flags;
	int retry = 0;
	int ret, i;
	int zero = 0, ff = 0;
	LIST_HEAD(req_list);

	spin_lock_irqsave(&hpb->hpb_lock, flags);
	list_splice_init(&hpb->lh_cpage_req,
			&req_list);
	spin_unlock_irqrestore(&hpb->hpb_lock, flags);

	list_for_each_entry_safe(cp, next_cp, &req_list, list_cpage) {
		unsigned char cmd[10] = { 0 };
		int length = 512 * 1024;

		ufshpb_set_read_buf_cmd(cmd, cp->cblk, cp->cpage, length);

		debugk(hpb, "%s:%d ISSUE READ_BUFFER : %d - %d [%d] %llx [%d] %llx\n",
				__func__, __LINE__,	cp->cblk, cp->cpage,
				0, cp->td->ppn_table[0], (hpb->entries_per_cpage - 1),
				cp->td->ppn_table[hpb->entries_per_cpage - 1]);

		TMSG(hpb, "UFSHPB ISSUE READ BUFFER %d - %d : %p [%d] %llx [%d] %llx",
				cp->cblk, cp->cpage, cp->td->ppn_table,
				0, cp->td->ppn_table[0], (hpb->entries_per_cpage - 1),
				cp->td->ppn_table[hpb->entries_per_cpage - 1]);
		ret = ufshpb_execute_req(hpb, cmd,
				cp->td->ppn_table, length);
		TMSG(hpb, "UFSHPB COMPL READ BUFFER %d - %d : %p [%d] %llx [%d] %llx",
				cp->cblk, cp->cpage, cp->td->ppn_table,
				0, cp->td->ppn_table[0], (hpb->entries_per_cpage - 1),
				cp->td->ppn_table[hpb->entries_per_cpage - 1]);

		if (hpb->debug) {
			for (i = 0 ; i < hpb->entries_per_cpage ; i++) {
				if (cp->td->ppn_table[i] == 0)
					zero++;
				if (cp->td->ppn_table[i] == 0xffffffff)
					ff++;
			}
		}

		debugk(hpb, "%s:%d COMPL READ_BUFFER %d - %d [%d] %llx [%d] %llx zero %d ff %d\n",
				__func__, __LINE__,	cp->cblk, cp->cpage,
				0, cp->td->ppn_table[0], (hpb->entries_per_cpage - 1),
				cp->td->ppn_table[hpb->entries_per_cpage - 1], zero, ff);

		if (ret < 0) {
			printk("%s: failed with err %d retry %d\n", __func__, ret, retry++);
			if (retry >= 3) {
				dev_warn(hpb->hba->dev,
						"UFSHPB read buffer command failed (%d)\n", ret);
				return ret;
			}

			spin_lock_irqsave(&hpb->hpb_lock, flags);
			list_add_tail(&cp->list_cpage, &hpb->lh_cpage_req);
			spin_unlock_irqrestore(&hpb->hpb_lock, flags);
			continue;
		}

		ufshpb_clean_cache_page(hpb, cp);
		list_del_init(&cp->list_cpage);
	}

	return 0;
}

static void ufshpb_work_handler(struct work_struct *work)
{
	struct ufshpb_lu *hpb;
	int ret;

	hpb = container_of(work, struct ufshpb_lu, ufshpb_work);
	debugk(hpb, "%s:%d worker start\n", __func__, __LINE__);

	if (!list_empty(&hpb->lh_cpage_req)) {
		ret = ufshpb_issue_map_req_from_list(hpb);
		/*
		 * if its function failed at init time,
		 * ufshpb-device will request map-req,
		 * so it is not critical-error, and just finish work-handler
		 */
		if (ret)
			debugk(hpb, "%s:%d failed map-issue. ret %d\n",
					__func__, __LINE__, ret);
	}

	debugk(hpb, "%s:%d worker end\n", __func__, __LINE__);
	return;
}

static void ufshpb_init_constant(void)
{
	sects_per_blk_shift = ffs(BLOCK) - ffs(SECTOR);
	printk("%s:%d sects_per_blk_shift: %u %u\n", __func__, __LINE__,
			sects_per_blk_shift,
			ffs(SECTORS_PER_BLOCK) - 1);

	bits_per_dword_shift = ffs(BITS_PER_DWORD) - 1;
	bits_per_dword_mask = BITS_PER_DWORD - 1;
	printk("%s:%d bits_per_dword %u shift %u mask 0x%X\n",
			__func__, __LINE__, BITS_PER_DWORD,
			bits_per_dword_shift, bits_per_dword_mask);

	bits_per_byte_shift = ffs(BITS_PER_BYTE) - 1;
	printk("%s:%d bits_per_byte %u shift %u\n",
			__func__, __LINE__, BITS_PER_BYTE, bits_per_dword_shift);
}

static void ufshpb_table_mempool_remove(struct ufshpb_lu *hpb)
{
	struct ufshpb_tdata *td, *next;

	list_for_each_entry_safe(td, next, &hpb->lh_free_table, list_table) {
		kfree(td->ppn_table);
		vfree(td->ppn_dirty);
		kfree(td);
		alloc_td--;
	}
}

static void ufshpb_init_map_request(struct ufs_hba *hba,
		struct ufshpb_lu *hpb)
{
	int i;

	hpb->map_idx = 0;

	for (i = 0 ; i < MAX_MAP_REQ ; i++) {
		struct ufshpb_map_req *map_req;

		map_req = hpb->map_req + i;

		map_req->hpb = hpb;
		map_req->end_io = NULL;
		map_req->end_io_data = NULL;
		map_req->p = NULL;
		map_req->cblk = -1;
		map_req->cpage = -1;
		memset(&map_req->req, 0x00, sizeof(struct request));
	}
}

static int ufshpb_init_cache_block(struct ufshpb_lu *hpb,
		struct ufshpb_cblock *cb, bool pinned, bool load)
{
	struct ufshpb_cpage *cp;
	int cpage, j;
	unsigned long flags;
	int err = 0;

	for (cpage = 0 ; cpage < cb->cpage_count ; cpage++) {
		cp = cb->cpage_tbl + cpage;

		cp->td = ufshpb_get_table_data(hpb, &err);
		if (err) {
			printk("%s:%d get td failed. err %d cpage %d free_table %d\n",
					__func__, __LINE__, err, cpage, hpb->debug_free_table);
			goto release;
		}

		if (load) {
			spin_lock_irqsave(&hpb->hpb_lock, flags);
			ufshpb_add_cpage_to_req_list(hpb, cp);
			spin_unlock_irqrestore(&hpb->hpb_lock, flags);
		}
	}

	if (pinned)
		cb->cblk_state = CBLK_PINNED;
	else
		cb->cblk_state = CBLK_CACHED;

	return 0;
release:
	for (j = 0 ; j < cpage ; j++) {
		cp = cb->cpage_tbl + j;
		ufshpb_put_table_data(hpb, cp->td);
	}

	return err;
}

static inline bool ufshpb_is_cblk_pinned(
		struct ufshpb_lu_desc *lu_desc, int cblk)
{
	if (cblk >= lu_desc->lu_hpb_pinned_start_offset &&
				cblk <= lu_desc->lu_hpb_pinned_end_offset)
		return true;

	return false;
}

static void ufshpb_init_cpage_tbl(struct ufshpb_lu *hpb,
		struct ufshpb_cblock *cb)
{
	int cpage;

	for (cpage = 0 ; cpage < cb->cpage_count ; cpage++) {
		struct ufshpb_cpage *cp
			= cb->cpage_tbl + cpage;

		cp->cblk= cb->cblk;
		cp->cpage= cpage;
		cp->cpage_state = CPAGE_UNUSED;
	}
}

static inline int ufshpb_alloc_cpage_tbl(struct ufshpb_lu *hpb,
		struct ufshpb_cblock *cb, int cpage_count)
{
	cb->cpage_tbl = kzalloc(
			sizeof(struct ufshpb_cpage) * cpage_count,
			GFP_KERNEL);
	if (!cb->cpage_tbl)
		return -ENOMEM;

	cb->cpage_count = cpage_count;
	debugk(hpb, "%s:%d cblk %d cpage_count %d cache_page_table bytes %lu\n",
			__func__, __LINE__,
			cb->cblk, cpage_count,
			sizeof(struct ufshpb_cpage *) * hpb->cpages_per_cblk);

	return 0;
}

static void ufshpb_table_mempool_init(struct ufshpb_lu *hpb,
		int num_cblks, int cpages_per_cblk,
		int entry_count, int entry_byte)
{
	int i;

	INIT_LIST_HEAD(&hpb->lh_free_table);

	for (i = 0 ; i < num_cblks * cpages_per_cblk ; i++) {
		struct ufshpb_tdata *td = kmalloc(sizeof(struct ufshpb_tdata), GFP_KERNEL);

		td->ppn_table = kzalloc(entry_count * entry_byte, GFP_KERNEL);
		td->ppn_dirty = vzalloc(entry_count >> bits_per_byte_shift);
		INIT_LIST_HEAD(&td->list_table);

		list_add(&td->list_table, &hpb->lh_free_table);
		hpb->debug_free_table++;
	}

	alloc_td = num_cblks * cpages_per_cblk;
	printk("%s:%d number of td %d %d %d. debug_free_table %d\n", __func__, __LINE__,
			num_cblks * cpages_per_cblk, num_cblks, cpages_per_cblk,
			hpb->debug_free_table);
}

static void ufshpb_init_lu_constant(struct ufshpb_lu *hpb,
		struct ufshpb_lu_desc *lu_desc,
		struct ufshpb_func_desc *func_desc)
{
	int cblk_size_byte, cblk_size_block;
	int entries_per_lu;

	cblk_size_byte = func_desc->hpb_cblk_size
		* func_desc->segment_size * SECTOR;
	/* Entires_per_cblk == The size [Block] of Cache Block */
	cblk_size_block = cblk_size_byte / BLOCK;

	hpb->entries_per_cblk = cblk_size_byte / func_desc->hpb_entry_byte;
	hpb->entries_per_cblk_shift = ffs(hpb->entries_per_cblk) - 1;
	hpb->entries_per_cblk_mask = hpb->entries_per_cblk - 1;

	/* Entires_per_LUN == The number of Logical Block in LU */
	entries_per_lu = lu_desc->lu_logblk_cnt;
	hpb->entries_per_lu = entries_per_lu; // for debugging
	/* Cache_Block_per_LUN =
	 * The number of Logical Block in LU / The size [Block] of Cache Block  */
	hpb->cblks_per_lu = (entries_per_lu + hpb->entries_per_cblk - 1)
		/ hpb->entries_per_cblk;

	hpb->cpages_per_cblk = func_desc->hpb_cpage_per_cblk;
	/* (entries_per_cblk = 1MB) / (cpages_per_cblk = 8) = 128K */
	hpb->entries_per_cpage = hpb->entries_per_cblk / hpb->cpages_per_cblk;
	hpb->entries_per_cpage_shift = ffs(hpb->entries_per_cpage) - 1;
	hpb->entries_per_cpage_mask = hpb->entries_per_cpage - 1;

	hpb->cpage_bytes = hpb->entries_per_cpage * func_desc->hpb_entry_byte;
	hpb->cpages_per_lu = (entries_per_lu + hpb->entries_per_cpage - 1)
		/ hpb->entries_per_cpage;
	hpb->dwords_per_cpage = hpb->entries_per_cpage / BITS_PER_DWORD;

	printk("%s:%d cblk_size_byte %u _block %u \n",
			__func__, __LINE__, cblk_size_byte, cblk_size_block);
	printk("%s:%d entries_per_cblk %u shift %u mask 0x%X\n",
			__func__, __LINE__,	hpb->entries_per_cblk,
			hpb->entries_per_cblk_shift, hpb->entries_per_cblk_mask);
	printk("%s:%d entries_per_lu %u cblks_per_lu %u\n",
			__func__, __LINE__,	entries_per_lu, hpb->cblks_per_lu);
	printk("%s:%d cpages_per_cblk %u\n",
			__func__, __LINE__, hpb->cpages_per_cblk);
	printk("%s:%d entries_per_cpage %u shift %u mask 0x%X\n",
			__func__, __LINE__, hpb->entries_per_cpage,
			hpb->entries_per_cpage_shift, hpb->entries_per_cpage_mask);
	printk("%s:%d cpage_bytes : %u\n", __func__, __LINE__, hpb->cpage_bytes);
	printk("%s:%d cpages_per_lu %u dwords_per_cpage: %u\n",
			__func__, __LINE__,	hpb->cpages_per_lu, hpb->dwords_per_cpage);
}

static int ufshpb_lu_hpb_init(struct ufs_hba *hba, struct ufshpb_lu *hpb,
		struct ufshpb_func_desc *func_desc, struct ufshpb_lu_desc *lu_desc)
{
	struct ufshpb_cblock *cblk_table, *cb;
	struct ufshpb_cpage *cp;
	int cblk, cpage;
	int total_cpage_count, cpage_count;
	bool do_work_handler;
	int ret, j;

	hpb->lu_hpb_enable = true;

	ufshpb_init_lu_constant(hpb, lu_desc, func_desc);

	cblk_table = kzalloc(sizeof(struct ufshpb_cblock) * hpb->cblks_per_lu,
			GFP_KERNEL);
	printk("%s:%d cache_block_table bytes: %lu \n", __func__, __LINE__,
			(sizeof(struct ufshpb_cblock) * hpb->cblks_per_lu));
	if (!cblk_table)
		goto out;

	hpb->cblk_tbl = cblk_table;

	spin_lock_init(&hpb->hpb_lock);

	INIT_LIST_HEAD(&hpb->lh_cpage_req);
	ufshpb_table_mempool_init(hpb,
			lu_desc->lu_hpb_num_cblks, hpb->cpages_per_cblk,
			hpb->entries_per_cpage, func_desc->hpb_entry_byte);

	total_cpage_count = hpb->cpages_per_lu;


	printk("%s:%d total_cpage_count: %d\n",
			__func__, __LINE__, total_cpage_count);
	for (cblk = 0, cpage_count = 0,
			total_cpage_count = hpb->cpages_per_lu
			; cblk < hpb->cblks_per_lu ;
			cblk++, total_cpage_count -= cpage_count) {
		struct ufshpb_cblock *cb;

		cb = cblk_table + cblk;
		cb->cblk = cblk;

		cpage_count = min(total_cpage_count, hpb->cpages_per_cblk);
		printk("%s:%d total: %d cpage_count: %d\n",
				__func__, __LINE__, total_cpage_count, cpage_count);

		ret = ufshpb_alloc_cpage_tbl(hpb, cb, cpage_count);
		if (ret)
			goto release_cblk_cp;
		ufshpb_init_cpage_tbl(hpb, cb);

		if (ufshpb_is_cblk_pinned(lu_desc, cblk)) {
			printk("%s:%d CBLK: %d PINNED %d ~ %d\n",
					__func__, __LINE__, cblk,
					lu_desc->lu_hpb_pinned_start_offset,
					lu_desc->lu_hpb_pinned_end_offset);
			ret = ufshpb_init_cache_block(hpb, cb, true, true);
			if (ret) {
				kfree(cb[cblk].cpage_tbl);
				goto release_cblk_cp;
			}
			do_work_handler = true;
		} else {
			printk("%s:%d CBLK: %d UNUSED\n",
					__func__, __LINE__,
					cb->cblk);
			cb->cblk_state = CBLK_UNUSED;
		}
	}

	if (total_cpage_count != 0) {
		printk("%s:%d error total_cpage_count: %d \n",
				__func__, __LINE__, total_cpage_count);
		goto release_cblk_cp;
	}

	INIT_WORK(&hpb->ufshpb_work, ufshpb_work_handler);
	hpb->hba = hba;
	hpb->debug = true;

	ufshpb_init_map_request(hba, hpb);
	if (do_work_handler)
		schedule_work(&hpb->ufshpb_work);

	/*
	 * even if creating sysfs failed, ufshpb could run normally.
	 * so we don't deal with error handling
	 * */
	ufshpb_create_sysfs(hba, hpb);
	return 0;
release_cblk_cp:
	for (j = 0 ; j < cblk ; j++) {
		cb = cblk_table + j;
		for (cpage = 0 ; cpage < cb->cpage_count ; cpage++) {
			cp = cb->cpage_tbl + cpage;

			if (cp->td)
				ufshpb_put_table_data(hpb, cp->td);
		}
		kfree(cb->cpage_tbl);
	}
	kfree(cblk_table);
	ufshpb_table_mempool_remove(hpb);
out:
	return ret;
}

static int ufshpb_get_hpb_lu_desc(struct ufs_hba *hba,
		struct ufshpb_lu_desc *lu_desc, int lun)
{
	int ret;
	u8 logical_buf[QUERY_DESC_UNIT_MAX_SIZE] = { 0 };

	ret = ufshcd_read_unit_desc(hba, lun, logical_buf,
				QUERY_DESC_UNIT_MAX_SIZE);
	if (ret)
		return ret;

	lu_desc->lu_enable = logical_buf[UNIT_DESC_PARAM_LU_ENABLE];
	lu_desc->lu_logblk_size = logical_buf[UNIT_DESC_PARAM_LOGICAL_BLK_SIZE]; // 2^log, ex) 0x0C = 4KB
	lu_desc->lu_logblk_cnt =
		(u64) logical_buf[UNIT_DESC_PARAM_LOGICAL_BLK_COUNT] << 56 |
		(u64) logical_buf[UNIT_DESC_PARAM_LOGICAL_BLK_COUNT + 1] << 48 |
		(u64) logical_buf[UNIT_DESC_PARAM_LOGICAL_BLK_COUNT + 2] << 40 |
		(u64) logical_buf[UNIT_DESC_PARAM_LOGICAL_BLK_COUNT + 3] << 32 |
		(u64) logical_buf[UNIT_DESC_PARAM_LOGICAL_BLK_COUNT + 4] << 24 |
		(u64) logical_buf[UNIT_DESC_PARAM_LOGICAL_BLK_COUNT + 5] << 16 |
		(u64) logical_buf[UNIT_DESC_PARAM_LOGICAL_BLK_COUNT + 6] << 8 |
		(u64) logical_buf[UNIT_DESC_PARAM_LOGICAL_BLK_COUNT + 7];

	lu_desc->lu_hpb_enable = logical_buf[UNIT_DESC_HPB_LU_ENABLE];
	lu_desc->lu_hpb_feature = logical_buf[UNIT_DESC_HPB_LU_FEATURE];
	lu_desc->lu_hpb_num_cblks =
		logical_buf[UNIT_DESC_HPB_LU_NUM_HPB_CACHE_BLKS];
	lu_desc->lu_hpb_pinned_start_offset =
		logical_buf[UNIT_DESC_HPB_LU_HPB_PIN_BLK_START];
	lu_desc->lu_hpb_pinned_end_offset =
		logical_buf[UNIT_DESC_HPB_LU_HPB_PIN_BLK_END];

	printk("%s:%d LUN(%d) [0A] bLogicalBlockSize %d\n",
			__func__, __LINE__, lun, lu_desc->lu_logblk_size);
	printk("%s:%d LUN(%d) [0B] qLogicalBlockCount %llu\n",
			__func__, __LINE__, lun, lu_desc->lu_logblk_cnt);
	printk("%s:%d LUN(%d) [23] bHPBLuEnable %d\n",
			__func__, __LINE__, lun, lu_desc->lu_hpb_enable);
	printk("%s:%d LUN(%d) [24] bUFSFLuFeature %d\n",
			__func__, __LINE__, lun, lu_desc->lu_hpb_feature);
	printk("%s:%d LUN(%d) [25] bNumHPBCacheBlks %d\n",
			__func__, __LINE__, lun, lu_desc->lu_hpb_num_cblks);
	printk("%s:%d LUN(%d) [26] bHPBPinnedCacheBlkStartOffset %d\n",
			__func__, __LINE__, lun, lu_desc->lu_hpb_pinned_start_offset);
	printk("%s:%d LUN(%d) [27] bHPBPinnedCacheBlkEndOffset %d\n",
			__func__, __LINE__, lun, lu_desc->lu_hpb_pinned_end_offset);

	return 0;
}

static int ufshpb_read_dev_desc_support(struct ufs_hba *hba,
		struct ufshpb_func_desc *desc)
{
	u8 desc_buf[QUERY_DESC_DEVICE_MAX_SIZE];
	int major, minor;
	int err;

	err = ufshcd_read_device_desc(hba, desc_buf,
			QUERY_DESC_DEVICE_MAX_SIZE);
	if (err)
		return err;

	if (desc_buf[DEVICE_DESC_PARAM_FEAT_SUP] & 0x20) {
		printk("%s:%d bUFSFeaturesSupport: HPB is set\n", __func__, __LINE__);
	} else {
		printk("%s:%d bUFSFeaturesSupport: HPB not support \n",
				__func__, __LINE__);
		return -ENODEV;
	}

	major = desc_buf[DEVICE_DESC_PARAM_HPB_VER + 1];
	minor = desc_buf[DEVICE_DESC_PARAM_HPB_VER];
	printk("%s:%d HPB major %x minor-suffix %.2x \n",
			__func__, __LINE__, major, minor);

	desc->lu_cnt = desc_buf[DEVICE_DESC_PARAM_NUM_LU];
	printk("%s:%d device lu count %d \n",
			__func__, __LINE__, desc->lu_cnt);

	return 0;
}

static int ufshpb_read_geo_desc_support(struct ufs_hba *hba,
		struct ufshpb_func_desc *desc)
{
	int err;
	u8 geometry_buf[QUERY_DESC_GEOMETRY_MAX_SIZE];

	err = ufshcd_read_geometry_desc(hba, geometry_buf,
				QUERY_DESC_GEOMETRY_MAX_SIZE);
	if (err)
		return err;

	desc->segment_size = (u32) geometry_buf[GEOMETRY_DESC_SEGMENT_SIZE] << 24 |
		(u32) geometry_buf[GEOMETRY_DESC_SEGMENT_SIZE + 1] << 16 |
		(u32) geometry_buf[GEOMETRY_DESC_SEGMENT_SIZE + 2] << 8 |
		(u32) geometry_buf[GEOMETRY_DESC_SEGMENT_SIZE + 3];

	desc->hpb_entry_byte = geometry_buf[GEOMETRY_DESC_HPB_ENTRY_SIZE];
	desc->hpb_cblk_size = geometry_buf[GEOMETRY_DESC_HPB_CACHE_BLOCK_SIZE];
	desc->hpb_number_lu = geometry_buf[GEOMETRY_DESC_HPB_NUMBER_LU];
//	desc->hpb_cpage_per_cblk = geometry_buf[GEOMETRY_DESC_HPB_NUM_CACHE_PAGE];
	desc->hpb_cpage_per_cblk = 16;
	desc->hpb_max_cblk = geometry_buf[GEOMETRY_DESC_HPB_MAX_CACHE_BLOCK];

	printk("%s:%d [0D] dSegmentSize %u\n",
			__func__, __LINE__, desc->segment_size);
	printk("%s:%d [48] bHPBEntrySize %u\n",
			__func__, __LINE__, desc->hpb_entry_byte);
	printk("%s:%d [49] bHPBCacheBlockSize %u\n",
			__func__, __LINE__, desc->hpb_cblk_size);
	printk("%s:%d [4A] bHPBNumberLU %u\n",
			__func__, __LINE__, desc->hpb_number_lu);
	printk("%s:%d [4B] bNumHPBCachePage %u\n",
			__func__, __LINE__, desc->hpb_cpage_per_cblk);
	printk("%s:%d [4C] bMaxHPBCacheBlock %u\n",
			__func__, __LINE__, desc->hpb_max_cblk);

	if (desc->hpb_number_lu == 0) {
		dev_warn(hba->dev, "UFSHPB) HPB is not supported\n");
		return -ENODEV;
	}

	return 0;
}

int ufshpb_init(struct ufs_hba *hba)
{
	struct ufshpb_func_desc func_desc;
	int lun, i;
	int hpb_dev = 0;
	int ret;

	ret = ufshpb_read_dev_desc_support(hba, &func_desc);
	if (ret)
		goto out_state;

	ret = ufshpb_read_geo_desc_support(hba, &func_desc);
	if (ret)
		goto out_state;

	for (lun = 0 ; lun < UFS_UPIU_MAX_GENERAL_LUN ; lun++) {
		struct ufshpb_lu_desc lu_desc;

		ret = ufshpb_get_hpb_lu_desc(hba, &lu_desc, lun);
		if (ret)
			goto out_state;

		if (!lu_desc.lu_enable || !lu_desc.lu_hpb_enable) {
			hba->ufshpb_lup[lun] = NULL;
			continue;
		}

		hba->ufshpb_lup[lun] = kzalloc(sizeof(struct ufshpb_lu), GFP_KERNEL);
		if (!hba->ufshpb_lup[lun])
			goto out_free_mem;

		ret = ufshpb_lu_hpb_init(hba, hba->ufshpb_lup[lun],
				&func_desc, &lu_desc);
		if (ret) {
			if (ret == -ENODEV)
				continue;
			else
				goto out_free_mem;
		}
		hpb_dev++;
	}

	if (hpb_dev == 0) {
		dev_warn(hba->dev, "No UFSHPB LU to init\n");
		ret = -ENODEV;
		goto out_free_mem;
	}

	ufshpb_init_constant();

	INIT_WORK(&hba->ufshpb_eh_work, ufshpb_error_handler);
	hba->ufshpb_state = HPB_PRESENT;

	for (lun = 0 ; lun < UFS_UPIU_MAX_GENERAL_LUN ; lun++) {
		if (hba->ufshpb_lup[lun]) {
			dev_info(hba->dev, "UFSHPB LU %d working\n", lun);
			dev_info(hba->dev, "UFSHPB LU %d %s:%s:%s\n",
					lun, hba->sdev_ufs_lu[lun]->vendor,
					hba->sdev_ufs_lu[lun]->model,
					hba->sdev_ufs_lu[lun]->rev);
		}
	}

	return 0;
out_free_mem:
	for (i = 0 ; i < lun ; i++)
		if (hba->ufshpb_lup[lun])
			kfree(hba->ufshpb_lup[lun]);
out_state:
	hba->ufshpb_state = HPB_NOT_SUPPORTED;
	return ret;
}

static void ufshpb_map_loading_trigger(struct ufshpb_lu *hpb,
		bool dirty, bool only_pinned)
{
	int cblk, cpage;
	unsigned long flags;
	bool do_work_handler = false;

	for (cblk = 0 ; cblk < hpb->cblks_per_lu ; cblk++) {
		struct ufshpb_cblock *cb;

		cb = hpb->cblk_tbl + cblk;

		if (cb->cblk_state == CBLK_CACHED ||
				cb->cblk_state == CBLK_PINNED) {
			printk("%s:%d add cache block number %d state %d\n",
					__func__, __LINE__, cblk, cb->cblk_state);
			if ((only_pinned && cb->cblk_state == CBLK_PINNED) ||
					!only_pinned) {
				spin_lock_irqsave(&hpb->hpb_lock, flags);
				for (cpage = 0 ; cpage < cb->cpage_count ; cpage++) {
					ufshpb_add_cpage_to_req_list(hpb, cb->cpage_tbl + cpage);
				}
				spin_unlock_irqrestore(&hpb->hpb_lock, flags);
				do_work_handler = true;
			}

			if (dirty) {
				for (cpage = 0 ; cpage < cb->cpage_count ; cpage++)
					cb->cpage_tbl[cpage].cpage_state = CPAGE_DIRTY;
			}

		}
	}

	if (do_work_handler)
		schedule_work(&hpb->ufshpb_work);
}

static void ufshpb_purge_cache_block(struct ufshpb_lu *hpb)
{
	int cblk, cpage;
	int state = -1;
	struct ufshpb_cblock *cb;
	struct ufshpb_cpage *cp;
	unsigned long flags;

	spin_lock_irqsave(&hpb->hpb_lock, flags);
	for (cblk = 0 ; cblk < hpb->cblks_per_lu ; cblk++) {
		cb = hpb->cblk_tbl + cblk;

		if (cb->cblk_state == CBLK_UNUSED) {
			debugk(hpb, "%s:%d cblk %d UNUSED\n", __func__, __LINE__, cblk);
			continue;
		}

		if (cb->cblk_state == CBLK_PINNED) {
			state = CPAGE_DIRTY;
		} else if (cb->cblk_state == CBLK_CACHED) {
			state = CPAGE_UNUSED;
			cb->cblk_state = CBLK_UNUSED;
		}

		debugk(hpb, "%s:%d cblk %d state %d dft %d\n",
				__func__, __LINE__, cblk, state, hpb->debug_free_table);
		for (cpage = 0 ; cpage < hpb->cpages_per_cblk ; cpage++) {
			cp = cb->cpage_tbl + cpage;

			ufshpb_purge_cache_page(hpb, cp, state);
		}
		debugk(hpb, "%s:%d cblk %d state %d dft %d\n",
				__func__, __LINE__, cblk, state, hpb->debug_free_table);
	}
	spin_unlock_irqrestore(&hpb->hpb_lock, flags);
}

void ufshpb_probe(struct ufs_hba *hba)
{
	struct ufshpb_lu *hpb;
	int lu;

	for (lu = 0 ; lu < UFS_UPIU_MAX_GENERAL_LUN ; lu++) {
		hpb = hba->ufshpb_lup[lu];

		if (hpb && hpb->lu_hpb_enable) {
			dev_info(hba->dev, "UFSHPB lun %d reset\n", lu);
			ufshpb_purge_cache_block(hpb);
//			ufshpb_map_loading_trigger(hpb, true, true);
		}
	}

	hba->ufshpb_state = HPB_PRESENT;
}

static void ufshpb_destroy_cpage_tbl(struct ufshpb_lu *hpb,
		struct ufshpb_cblock *cb)
{
	int cpage;

	for (cpage = 0 ; cpage < hpb->cpages_per_cblk ; cpage++) {
		struct ufshpb_cpage *cp;

		cp = cb->cpage_tbl + cpage;

		printk("%s:%d cp %d %p state %d td %p\n",
				__func__, __LINE__, cpage, cp, cp->cpage_state, cp->td);

		cp->cpage_state = CPAGE_UNUSED;

		ufshpb_put_table_data(hpb, cp->td);
	}

	kfree(cb->cpage_tbl);
}

static void ufshpb_destroy_cblk_tbl(struct ufshpb_lu *hpb)
{
	int cblk;

	for (cblk = 0 ; cblk < hpb->cblks_per_lu ; cblk++) {
		struct ufshpb_cblock *cb;

		cb = hpb->cblk_tbl + cblk;
		printk("%s:%d cblk %d %p state %d\n", __func__, __LINE__, cblk, cb,
				cb->cblk_state);

		if (cb->cblk_state == CBLK_PINNED ||
				cb->cblk_state == CBLK_CACHED) {
			cb->cblk_state = CBLK_UNUSED;

			ufshpb_destroy_cpage_tbl(hpb, cb);
		}
	}

	ufshpb_table_mempool_remove(hpb);
	kfree(hpb->cblk_tbl);
}

void ufshpb_release(struct ufs_hba *hba, int state)
{
	int lun;

	printk("%s:%d start release\n", __func__, __LINE__);
	hba->ufshpb_state = HPB_FAILED;

	for (lun = 0 ; lun < UFS_UPIU_MAX_GENERAL_LUN ; lun++) {
		struct ufshpb_lu *hpb = hba->ufshpb_lup[lun];

		printk("%s:%d lun %d %p\n",
				__func__, __LINE__, lun, hpb);

		hba->ufshpb_lup[lun] = NULL;

		if (!hpb)
			continue;

		if (!hpb->lu_hpb_enable)
			continue;

		hpb->lu_hpb_enable = false;

		cancel_work_sync(&hpb->ufshpb_work);

		ufshpb_destroy_cblk_tbl(hpb);

		kobject_uevent(&hpb->kobj, KOBJ_REMOVE);
		kobject_del(&hpb->kobj); // TODO count 낮추고 del?

		kfree(hpb);
	}

	if (alloc_td != 0)
		printk("%s:%d warning: alloc_td %d\n", __func__, __LINE__, alloc_td);

	hba->ufshpb_state = state;
}

static void ufshpb_error_handler(struct work_struct *work)
{
	struct ufs_hba *hba;

	hba = container_of(work, struct ufs_hba, ufshpb_eh_work);

	dev_warn(hba->dev, "UFSHPB driver has failed - "
			"but UFSHCD can run without UFSHPB\n");
	dev_warn(hba->dev, "UFSHPB will be removed from the kernel\n");

	ufshpb_release(hba, HPB_FAILED);
}

static ssize_t ufshpb_sysfs_debug_release_store(struct ufshpb_lu *hpb,
		const char *buf, size_t count)
{
	unsigned long value;

	printk("%s:%d start release function\n",
			__func__, __LINE__);

	if (kstrtoul(buf, 0, &value)) {
		printk("%s:%d kstrtoul error\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (value == 0xab) {
		printk("%s:%d magic number %lu release start\n",
				__func__, __LINE__,	value);
		goto err_out;
	} else {
		printk("%s:%d wrong magic number %lu\n",
				__func__, __LINE__, value);
	}

	return count;
err_out:
	hpb->hba->ufshpb_state = HPB_FAILED;
	schedule_work(&hpb->hba->ufshpb_eh_work);
	return count;
}

static ssize_t ufshpb_sysfs_info_lba_store(struct ufshpb_lu *hpb,
		const char *buf, size_t count)
{
	unsigned long long ppn;
	unsigned long value;
	unsigned long flags;
	unsigned int lpn;
	int cblk, cpage, cpage_offset;
	struct ufshpb_cblock *cb;
	struct ufshpb_cpage *cp;
	int dirty;

	if (kstrtoul(buf, 0, &value)) {
		printk("%s:%d kstrtoul error\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (value > hpb->entries_per_lu) {
		printk("%s:%d value %lu> entries_per_lu %d error \n",
				__func__, __LINE__, value, hpb->entries_per_lu);
		return -EINVAL;
	}
	lpn = value / SECTORS_PER_BLOCK;

	ufshpb_get_pos_from_lpn(hpb, lpn, &cblk, &cpage, &cpage_offset);

	cb = hpb->cblk_tbl + cblk;
	cp = cb->cpage_tbl + cpage;

	if (cb->cblk_state != CBLK_UNUSED) {
		ppn = cp->td->ppn_table[cpage_offset];
		spin_lock_irqsave(&hpb->hpb_lock, flags);
		dirty = ufshpb_is_page_dirty(hpb, cp, cpage_offset);
		spin_unlock_irqrestore(&hpb->hpb_lock, flags);
	} else {
		ppn = 0;
		dirty = -1;
	}

	printk("%s:%d sector %lu cblk %d state %d cpage %d state %d\n",
			__func__, __LINE__, value,
			cblk, cb->cblk_state, cpage, cp->cpage_state);
	printk("%s:%d sector %lu lpn %u ppn %llx dirty %d\n",
			__func__, __LINE__, value, lpn, ppn, dirty);
	return count;
}

static ssize_t ufshpb_sysfs_map_req_show(struct ufshpb_lu *hpb, char *buf)
{
	long long cnt;

	cnt = atomic64_read(&hpb->map_req_cnt);

	printk("%s:%d map_req count %lld\n",
			__func__, __LINE__,	cnt);

	return snprintf(buf, PAGE_SIZE, "%lld\n", cnt);
}

static ssize_t ufshpb_sysfs_count_reset_store(struct ufshpb_lu *hpb,
		const char *buf, size_t count)
{
	unsigned long debug;

	if (kstrtoul(buf, 0, &debug))
		return -EINVAL;

	atomic64_set(&hpb->hit, 0);
	atomic64_set(&hpb->miss, 0);
	atomic64_set(&hpb->map_req_cnt, 0);

	return count;
}

static ssize_t ufshpb_sysfs_add_evict_show(struct ufshpb_lu *hpb, char *buf)
{
	long long add, evict;

	add = atomic64_read(&hpb->cblk_add);
	evict = atomic64_read(&hpb->cblk_add);

	printk("%s:%d add %lld evict %lld\n",
			__func__, __LINE__,	add, evict);

	return snprintf(buf, PAGE_SIZE, "add %lld evict %lld\n", add, evict);
}

static ssize_t ufshpb_sysfs_hit_show(struct ufshpb_lu *hpb, char *buf)
{
	long long hit;

	hit = atomic64_read(&hpb->hit);

	printk("%s:%d hit %lld\n",
			__func__, __LINE__,	hit);

	return snprintf(buf, PAGE_SIZE, "%lld\n", hit);
}

static ssize_t ufshpb_sysfs_miss_show(struct ufshpb_lu *hpb, char *buf)
{
	long long miss;

	miss = atomic64_read(&hpb->miss);

	printk("%s:%d miss %lld\n",
			__func__, __LINE__,	miss);

	return snprintf(buf, PAGE_SIZE, "%lld\n", miss);
}

static ssize_t ufshpb_sysfs_cache_block_status_show(struct ufshpb_lu *hpb, char *buf)
{
	int ret = 0, count = 0, cblk;

	ret = sprintf(buf, "PINNED=%d CACHED=%d UNUSED=%d\n",
			CBLK_PINNED, CBLK_CACHED, CBLK_UNUSED);
	count = ret;

	for (cblk = 0 ; cblk < hpb->cblks_per_lu ; cblk++) {
		ret = sprintf(buf + count, "%d:%d ", cblk,
				hpb->cblk_tbl[cblk].cblk_state);
		count += ret;
	}

	ret = sprintf(buf + count, "\n");
	count += ret;

	return count;
}

static ssize_t ufshpb_sysfs_debug_store(struct ufshpb_lu *hpb,
		const char *buf, size_t count)
{
	unsigned long debug;

	if (kstrtoul(buf, 0, &debug))
		return -EINVAL;

	if (debug >= 1)
		hpb->debug = 1;
	else
		hpb->debug = 0;

	printk("%s:%d debug %d\n",
			__func__, __LINE__,	hpb->debug);
	return count;
}

static ssize_t ufshpb_sysfs_debug_show(struct ufshpb_lu *hpb, char *buf)
{
	printk("%s:%d debug %d\n",
			__func__, __LINE__,	hpb->debug);

	return snprintf(buf, PAGE_SIZE, "%d\n",	hpb->debug);
}

static ssize_t ufshpb_sysfs_map_loading_store(struct ufshpb_lu *hpb,
		const char *buf, size_t count)
{
	unsigned long value;

	debugk(hpb, "%s:%d\n", __func__, __LINE__);

	if (kstrtoul(buf, 0, &value))
		return -EINVAL;

	if (value > 1)
		return -EINVAL;

	debugk(hpb, "%s:%d value %lu \n", __func__, __LINE__, value);

	if (value == 1)
		ufshpb_map_loading_trigger(hpb, false, false);

	return count;

}

static ssize_t ufshpb_sysfs_map_disable_show(struct ufshpb_lu *hpb, char *buf)
{
	return snprintf(buf, PAGE_SIZE,
			">> force_map_req_disable: %d\n", hpb->force_map_req_disable);
}

static ssize_t ufshpb_sysfs_map_disable_store(struct ufshpb_lu *hpb,
		const char *buf, size_t count)
{
	unsigned long value;

	if (kstrtoul(buf, 0, &value))
		return -EINVAL;

	if (value > 1)
		value = 1;

	if (value == 1)
		hpb->force_map_req_disable = true;
	else if (value == 0)
		hpb->force_map_req_disable = false;
	else
		debugk(hpb, "error value: %lu\n", value);
	debugk(hpb, "force_map_req_disable: %d\n", hpb->force_map_req_disable);

	return count;
}

static ssize_t ufshpb_sysfs_disable_show(struct ufshpb_lu *hpb, char *buf)
{
	return snprintf(buf, PAGE_SIZE,
			">> force_disable: %d\n",	hpb->force_disable);
}

static ssize_t ufshpb_sysfs_disable_store(struct ufshpb_lu *hpb,
		const char *buf, size_t count)
{
	unsigned long value;

	if (kstrtoul(buf, 0, &value))
		return -EINVAL;

	if (value > 1)
		value = 1;

	if (value == 1)
		hpb->force_disable = true;
	else if (value == 0)
		hpb->force_disable = false;
	else
		debugk(hpb, "error value: %lu\n", value);
	debugk(hpb, "force_disable: %d\n", hpb->force_disable);

	return count;
}

static int global_cblk;

static inline bool is_cblk_caching(struct ufshpb_lu *hpb, int cblk)
{
	if (hpb->cblk_tbl[cblk].cblk_state == CBLK_CACHED ||
			hpb->cblk_tbl[cblk].cblk_state == CBLK_PINNED)
		return true;

	return false;
}

static ssize_t ufshpb_sysfs_cache_group_store(struct ufshpb_lu *hpb,
		const char *buf, size_t count)
{
	unsigned long block;
	int cblk;

	if (kstrtoul(buf, 0, &block))
		return -EINVAL;

	cblk = block >> hpb->entries_per_cblk_shift;
	if (cblk >= hpb->cblks_per_lu) {
		printk("%s:%d error cblk %d max %d\n",
				__func__, __LINE__, cblk, hpb->cblks_per_lu);
		cblk = hpb->cblks_per_lu - 1;
	}

	global_cblk = cblk;

	printk("%s:%d block %lu cblk %d caching %d\n", __func__, __LINE__,
			block, cblk, is_cblk_caching(hpb, cblk));

	return count;
}

static ssize_t ufshpb_sysfs_cache_group_show(struct ufshpb_lu *hpb, char *buf)
{
	printk("%s:%d cblk %d caching %d\n", __func__, __LINE__,
			global_cblk, is_cblk_caching(hpb, global_cblk));

	return snprintf(buf, PAGE_SIZE,
		"%d\n",	is_cblk_caching(hpb, global_cblk));
}

static struct ufshpb_sysfs_entry ufshpb_sysfs_entries[] = {
	__ATTR(is_cache_group, S_IRUGO | S_IWUSR,
			ufshpb_sysfs_cache_group_show, ufshpb_sysfs_cache_group_store),
	__ATTR(read_16_disable, S_IRUGO | S_IWUSR,
			ufshpb_sysfs_disable_show, ufshpb_sysfs_disable_store),
	__ATTR(map_cmd_disable, S_IRUGO | S_IWUSR,
			ufshpb_sysfs_map_disable_show, ufshpb_sysfs_map_disable_store),
	__ATTR(map_loading, S_IWUSR, NULL, ufshpb_sysfs_map_loading_store),
	__ATTR(debug, S_IRUGO | S_IWUSR,
			ufshpb_sysfs_debug_show, ufshpb_sysfs_debug_store),
	__ATTR(cache_block_status, S_IRUGO,
			ufshpb_sysfs_cache_block_status_show, NULL),
	__ATTR(hit_count, S_IRUGO, ufshpb_sysfs_hit_show, NULL),
	__ATTR(miss_count, S_IRUGO, ufshpb_sysfs_miss_show, NULL),
	__ATTR(add_evict_count, S_IRUGO, ufshpb_sysfs_add_evict_show, NULL),
	__ATTR(count_reset, S_IWUSR, NULL, ufshpb_sysfs_count_reset_store),
	__ATTR(map_req_count, S_IRUGO, ufshpb_sysfs_map_req_show, NULL),
	__ATTR(get_info_from_lba, S_IWUSR, NULL, ufshpb_sysfs_info_lba_store),
	__ATTR(release, S_IWUSR, NULL, ufshpb_sysfs_debug_release_store),
	__ATTR_NULL
};

static ssize_t
ufshpb_attr_show(struct kobject *kobj,
		struct attribute *attr, char *page)
{
	struct ufshpb_sysfs_entry *entry;
	struct ufshpb_lu *hpb;
	ssize_t error;

	entry = container_of(attr,
			struct ufshpb_sysfs_entry, attr);
	hpb = container_of(kobj, struct ufshpb_lu, kobj);

	if (!entry->show)
		return -EIO;

	mutex_lock(&hpb->sysfs_lock);
	error = entry->show(hpb, page);
	mutex_unlock(&hpb->sysfs_lock);
	return error;
}

static ssize_t
ufshpb_attr_store(struct kobject *kobj,
		struct attribute *attr,
		const char *page, size_t length)
{
	struct ufshpb_sysfs_entry *entry;
	struct ufshpb_lu *hpb;
	ssize_t error;

	entry = container_of(attr,
			struct ufshpb_sysfs_entry, attr);
	hpb = container_of(kobj,
			struct ufshpb_lu, kobj);

	if (!entry->store)
		return -EIO;

	mutex_lock(&hpb->sysfs_lock);
	error = entry->store(hpb, page, length);
	mutex_unlock(&hpb->sysfs_lock);
	return error;
}

static struct sysfs_ops ufshpb_sysfs_ops = {
	.show = ufshpb_attr_show,
	.store = ufshpb_attr_store,
};

static struct kobj_type ufshpb_ktype = {
	.sysfs_ops = &ufshpb_sysfs_ops,
	.release = NULL,
};

static int ufshpb_create_sysfs(struct ufs_hba *hba,
		struct ufshpb_lu *hpb)
{
	struct device *dev = hba->dev;
	struct ufshpb_sysfs_entry *entry;
	int err;

	hpb->sysfs_entries = ufshpb_sysfs_entries;

	atomic64_set(&hpb->hit, 0);
	atomic64_set(&hpb->miss, 0);
	atomic64_set(&hpb->map_req_cnt, 0);
	atomic64_set(&hpb->cblk_evict, 0);
	atomic64_set(&hpb->cblk_add, 0);

	kobject_init(&hpb->kobj, &ufshpb_ktype);
	mutex_init(&hpb->sysfs_lock);

	debugk(hpb, "ufshpb creates sysfs ufshpb_lu %d %p dev->kobj %p\n",
			hpb->lun, &hpb->kobj, &dev->kobj);

	err = kobject_add(&hpb->kobj, kobject_get(&dev->kobj),
			"ufshpb_lu%d", hpb->lun);
	if (!err) {
		for (entry = hpb->sysfs_entries ;
				entry->attr.name != NULL ; entry++) {
			debugk(hpb, "ufshpb_lu%d sysfs attr creates: %s\n",
					hpb->lun, entry->attr.name);
			if (sysfs_create_file(&hpb->kobj, &entry->attr))
				break;
		}
		debugk(hpb, "ufshpb_lu%d sysfs adds uevent\n", hpb->lun);
		kobject_uevent(&hpb->kobj, KOBJ_ADD);
	}

	return err;
}
