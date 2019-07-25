#ifndef _RAINBOW_RESET_DETECT_API_H
#define _RAINBOW_RESET_DETECT_API_H
#ifdef CONFIG_RAINBOW_RESET_DETECT
#include <linux/types.h>

#define FD_M_NORMAL		0
#define FD_M_APANIC     1
#define FD_M_AWDT		2
#define FD_M_TZ			3
#define FD_M_SBL1		4
#define FD_M_ABL1		5
#define FD_M_UNKOWN     6
#define FD_M_MAX        7

//FD_M_NORMAL
#define FD_S_NORMAL     0
#define FD_S_NORMAL_UNKOWN     1

//FD_M_APANIC
#define FD_S_APANIC_PAGING_REQUEST		0
#define FD_S_APANIC_NULL_POINTER		1
#define FD_S_APANIC_BAD_MODE			2
#define FD_S_APANIC_HUNGTASK			3
#define FD_S_APANIC_OUT_OF_MEMORY		4
#define FD_S_APANIC_UNDEF_CMD			5
#define FD_S_APANIC_BUG				    6
#define FD_S_APANIC_SPINLOCK_DEBUG		7
#define FD_S_APANIC_UNHANDLE_FAULT		8
#define FD_S_APANIC_PREFETCH_ABORT		9
#define FD_S_APANIC_THERMAL			    10
#define FD_S_SUBSYSTEM_MODEM_CRASH		11
#define FD_S_SUBSYSTEM_ADSP_CRASH		12
#define FD_S_SUBSYSTEM_WCNSS_CRASH		13
#define FD_S_SUBSYSTEM_VENUS_CRASH		14
#define FD_S_SUBSYSTEM_UNKOWN_CRASH     15
#define FD_S_COMBIN_KEY					16
#define FD_S_APANIC_UNKOWN              17

//FD_M_AWDT
#define FD_S_AWDT				0
#define FD_S_AWDT_UNKOWN        1

//FD_M_TZ
#define FD_S_TZBSP_ERR_FATAL_NONE                         0
#define FD_S_TZBSP_ERR_FATAL_NON_SECURE_WDT               1
#define FD_S_TZBSP_ERR_FATAL_SECURE_WDT                   2
#define FD_S_TZBSP_ERR_FATAL_AHB_TIMEOUT                  3
#define FD_S_TZBSP_ERR_FATAL_RPM_WDOG                     4
#define FD_S_TZBSP_ERR_FATAL_RPM_ERR                      5
#define FD_S_TZBSP_ERR_FATAL_NOC_ERROR                    6
#define FD_S_TZBSP_ERR_FATAL_BIMC_ERROR                   7
#define FD_S_TZBSP_ERR_FATAL_SMEM                         8
#define FD_S_TZBSP_ERR_FATAL_XPU_VIOLATION                9
#define FD_S_TZBSP_ERR_FATAL_SMMU_FAULT                   10
#define FD_S_TZBSP_ERR_FATAL_QSEE_ERR                     11
#define FD_S_TZBSP_ERR_FATAL_EL3_SP_EL0_SYNCH             12
#define FD_S_TZBSP_ERR_FATAL_EL3_SP_EL0_IRQ               13
#define FD_S_TZBSP_ERR_FATAL_EL3_SP_EL0_FIQ               14
#define FD_S_TZBSP_ERR_FATAL_EL3_SP_EL0_ERR               15
#define FD_S_TZBSP_ERR_FATAL_EL3_SP_EL3_SYNCH             16
#define FD_S_TZBSP_ERR_FATAL_EL3_SP_EL3_IRQ               17
#define FD_S_TZBSP_ERR_FATAL_EL3_SP_EL3_FIQ               18
#define FD_S_TZBSP_ERR_FATAL_EL3_SP_EL3_ERR               19
#define FD_S_TZBSP_ERR_FATAL_EL3_LEL64_SYNCH              20
#define FD_S_TZBSP_ERR_FATAL_EL3_LEL64_IRQ                21
#define FD_S_TZBSP_ERR_FATAL_EL3_LEL64_FIQ                22
#define FD_S_TZBSP_ERR_FATAL_EL3_LEL64_ERR                23
#define FD_S_TZBSP_ERR_FATAL_EL3_LEL32_SYNCH              24
#define FD_S_TZBSP_ERR_FATAL_EL3_LEL32_IRQ                25
#define FD_S_TZBSP_ERR_FATAL_EL3_LEL32_FIQ                26
#define FD_S_TZBSP_ERR_FATAL_EL3_LEL32_ERR                27
#define FD_S_TZBSP_ERR_FATAL_EL1_SP_EL0_SYNCH             28
#define FD_S_TZBSP_ERR_FATAL_EL1_SP_EL0_IRQ               29
#define FD_S_TZBSP_ERR_FATAL_EL1_SP_EL0_FIQ               30
#define FD_S_TZBSP_ERR_FATAL_EL1_SP_EL0_ERR               31
#define FD_S_TZBSP_ERR_FATAL_EL1_SP_EL1_SYNCH             32
#define FD_S_TZBSP_ERR_FATAL_EL1_SP_EL1_IRQ               33
#define FD_S_TZBSP_ERR_FATAL_EL1_SP_EL1_FIQ               34
#define FD_S_TZBSP_ERR_FATAL_EL1_SP_EL1_ERR               35
#define FD_S_TZBSP_ERR_FATAL_EL1_LEL64_SYNCH              36
#define FD_S_TZBSP_ERR_FATAL_EL1_LEL64_IRQ                37
#define FD_S_TZBSP_ERR_FATAL_EL1_LEL64_FIQ                38
#define FD_S_TZBSP_ERR_FATAL_EL1_LEL64_ERR                39
#define FD_S_TZBSP_ERR_FATAL_EL1_LEL32_SYNCH              40
#define FD_S_TZBSP_ERR_FATAL_EL1_LEL32_IRQ                41
#define FD_S_TZBSP_ERR_FATAL_EL1_LEL32_FIQ                42
#define FD_S_TZBSP_ERR_FATAL_EL1_LEL32_ERR                43
#define FD_S_TZBSP_ERR_FATAL_RPM_DRIVER_ERR               44
#define FD_S_TZBSP_ERR_FATAL_RESET_TIMER_EXP              45
#define FD_S_TZBSP_ERR_FATAL_ICE_ERR                      46
#define FD_S_TZBSP_ERR_FATAL_LMH_DRIVER_ERR               47
#define FD_S_TZBSP_ERR_FATAL_ACCESS_CONTROL               48
#define FD_S_TZBSP_ERR_FATAL_CLOCK                        49
#define FD_S_TZBSP_ERR_FATAL_GIC_CPU_MAP_INVALID          50
#define FD_S_TZBSP_ERR_FATAL_SEC_WDT_TIMER_TRIGGER        51
#define FD_S_TZBSP_ERR_FATAL_FAULT_DETECTED               52
#define FD_S_TZBSP_ERR_UNKOWN                             53

void rainbow_reset_detect_m_reason_set(uint32_t reason);
void rainbow_reset_detect_s_reason_set(uint32_t reason);
void rainbow_reset_detect_s_reason_str_set(char *reason_s_info);
void rainbow_reset_detect_s_reason_str_set_format(const char *fmt, ...);
void rainbow_reset_detect_reason_info_str_set(char *reason_s_info);
void rainbow_reset_detect_reason_info_str_set_format(const char *fmt, ...);
void rainbow_reset_detect_reason_info_regs_kallsyms_set(const char *fmt, unsigned long addr);
void rainbow_reset_detect_show(void);
#endif
#endif