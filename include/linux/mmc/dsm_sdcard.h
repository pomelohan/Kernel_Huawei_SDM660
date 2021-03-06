#ifdef CONFIG_HUAWEI_SDCARD_DSM
#ifndef LINUX_MMC_DSM_SDCARD_H
#define LINUX_MMC_DSM_SDCARD_H

#include <dsm/dsm_pub.h>

#define DSM_REPORT_UEVENT_TRUE 		  1
#define DSM_REPORT_UEVENT_FALSE		  0
#define SDCARD_MSG_MAX_SIZE 200

enum DSM_SDCARD_STATUS
{
	DSM_SDCARD_CMD8				= 0,
	DSM_SDCARD_CMD55			= 1,
	DSM_SDCARD_ACMD41			= 2,
	DSM_SDCARD_CMD2_R0 			= 3,
	DSM_SDCARD_CMD2_R1 			= 4,
	DSM_SDCARD_CMD2_R2 			= 5,
	DSM_SDCARD_CMD2_R3 			= 6,
	DSM_SDCARD_CMD3    			= 7,
	DSM_SDCARD_CMD9_R0			= 8,
	DSM_SDCARD_CMD9_R1			= 9,
	DSM_SDCARD_CMD9_R2			= 10,
	DSM_SDCARD_CMD9_R3			= 11,
	DSM_SDCARD_CMD7				= 12,
	DSM_SDCARD_CMD6_CMDERR      = 13,
	DSM_SDCARD_CMD6_DATERR      = 14,
	DSM_SDCARD_STATUS_BLK_STUCK_IN_PRG_ERR	= 15,
	DSM_SDCARD_STATUS_BLK_WR_SPEED_ERR		= 16,
	DSM_SDCARD_STATUS_BLK_RW_CHECK_ERR		= 17,
	DSM_SDCARD_STATUS_RO_ERR				= 18,
	DSM_SDCARD_STATUS_FILESYSTEM_ERR		= 19,
	DSM_SDCARD_STATUS_LOWSPEED_SPEC_ERR     = 20,	/*reality this not report dot in code*/
	DSM_SDCARD_REPORT_UEVENT      			= 21,
	DSM_SDCARD_STATUS_HARDWARE_TIMEOUT_ERR	= 22,
	DSM_SDCARD_STATUS_MMC_BLK_ABORT			= 23,
	DSM_SDCARD_CMD_MAX,
};

enum DSM_SDCARD_ERR
{
	DSM_SDCARD_CMD2_RESP_ERR		= 928006000,
	DSM_SDCARD_CMD3_RESP_ERR,
	DSM_SDCARD_CMD6_RESP_ERR        = 928006002,
	DSM_SDCARD_CMD7_RESP_ERR        = 928006003,
	DSM_SDCARD_CMD8_RESP_ERR,
	DSM_SDCARD_CMD9_RESP_ERR,
	DSM_SDCARD_CMD55_RESP_ERR,
	DSM_SDCARD_ACMD41_RESP_ERR,
	DSM_SDCARD_BLK_STUCK_IN_PRG_ERR	= 928006008,
	DSM_SDCARD_BLK_WR_SPEED_ERR		= 928006009,
	DSM_SDCARD_BLK_RW_CHECK_ERR		= 928006010,
	DSM_SDCARD_RO_ERR				= 928006011,
	DSM_SDCARD_FILESYSTEM_ERR		= 928006012,
	DSM_SDCARD_LOWSPEED_SPEC_ERR	= 928006013,	/*reality this not report dot in code*/
	DSM_SDCARD_NO_UEVENT_REPORT     = 928006014,
	DMS_SDCARD_HARDWARE_TIMEOUT_ERR = 928006023,
	DMS_SDCARD_MMC_BLK_ABORT,
};

struct dsm_sdcard_cmd_log
{
	char *log;
	u32  value;
	u32  manfid;
};

extern struct dsm_client *sdcard_dclient;
extern u32  sd_manfid;
extern char g_dsm_log_sum[1024];
extern struct dsm_sdcard_cmd_log dsm_sdcard_cmd_logs[];

extern char *dsm_sdcard_get_log(int cmd,int err);

extern void sdcard_dsm_dclient_init(void);
extern void sdcard_cmd9_resp_err_dsm(struct mmc_host *host, struct mmc_card *card, int err);
extern void sdcard_dsm_cmd_logs_init(struct mmc_host *host, u32 cid);
extern void sdcard_dsm_cmd_logs_clear(struct mmc_host *host);
extern void set_dsm_sdcard_cmd_log_value(struct mmc_card *card,
		struct mmc_host *host, u32 type, u32 value);
extern void sdcard_no_uevent_report_dsm(struct mmc_card *card);
extern void sdcard_cmd2_resp_err_dsm(struct mmc_host *host, struct mmc_command *cmd, int err);
extern void sdcard_cmd7_resp_err_dsm(struct mmc_host *host, struct mmc_command *cmd, int err);
extern int sdcard_cmd55_resp_err_dsm(struct mmc_host *host, struct mmc_command *cmd, int err);
extern void sdcard_cmd41_resp_err_dsm(struct mmc_host *host, struct mmc_command *cmd, int err);
extern void sdcard_cmd3_resp_err_dsm(struct mmc_host *host, struct mmc_command *cmd, int err);
extern void sdcard_cmd8_resp_err_dsm(struct mmc_host *host, struct mmc_command *cmd, int err);
extern void dsm_sdcard_report(int cmd, int err);
#define DSM_SDCARD_LOG(error_num, fmt, a...) \
	do { \
		if(!dsm_client_ocuppy(sdcard_dclient)) { \
			dsm_client_record(sdcard_dclient, fmt, ## a); \
			dsm_client_notify(sdcard_dclient, error_num); } \
	}while(0)

#endif /* LINUX_MMC_DSM_SDCARD_H */
#endif /* CONFIG_HUAWEI_SDCARD_DSM */


