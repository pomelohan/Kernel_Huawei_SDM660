#ifndef RAINBOW_RESET_DETECT_H
#define RAINBOW_RESET_DETECT_H

#include <linux/types.h>

#define RAINBOW_RESET_DETECT_ADDR 0xA8600000
#define RAINBOW_RESET_DETECT_SIZE 0x8000

#define FD_S_MAX                999

#define RESET_DETECT_REASON_STR_MAX 128
#define RESET_DETECT_PMIC_REASON_STR_MAX 32

#define FD_S_REASON_STR_FLAG 2
#define FD_INFO_REASON_STR_FLAG 4

typedef struct
{
	uint32_t reset_reason_m_magic;						//kernel but sbl1 may be modify it
	uint32_t reset_reason_s_magic;						//kernel
	char reset_s_reason[RESET_DETECT_REASON_STR_MAX];	//kernel
	char reset_reason_info[RESET_DETECT_REASON_STR_MAX];//kernel

	char pon_reason1_str[RESET_DETECT_PMIC_REASON_STR_MAX];			//sbl
	char warm_reset_reason1_str[RESET_DETECT_PMIC_REASON_STR_MAX];  //sbl
	char poff_reason1_str[RESET_DETECT_PMIC_REASON_STR_MAX];        //sbl
	char fault_reason1[RESET_DETECT_PMIC_REASON_STR_MAX];           //sbl
	char fault_reason2[RESET_DETECT_PMIC_REASON_STR_MAX];           //sbl
	char s3_reset_reason_str[RESET_DETECT_PMIC_REASON_STR_MAX];     //sbl

	char last_reset_reason_m_str[RESET_DETECT_PMIC_REASON_STR_MAX]; //sbl
	uint32_t reset_reason_str_ready_flag;                           //kernel,lk,sbl
	uint32_t reset_reason_magic;//reset_reason_m_magic+100*reset_reason_s_magic    //sbl1
}reset_detect_info;
#endif