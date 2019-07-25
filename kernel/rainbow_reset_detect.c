#include "rainbow_reset_detect.h"
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <asm/stacktrace.h>
#include <linux/rainbow_reset_detect_api.h>

reset_detect_info * global_reset_detect_info_addr = NULL;

static reset_detect_info *rainbow_reset_detect_info_addr_map(void)
{
	if(global_reset_detect_info_addr==NULL)
	{
		global_reset_detect_info_addr = (reset_detect_info *)ioremap_nocache(RAINBOW_RESET_DETECT_ADDR,RAINBOW_RESET_DETECT_SIZE);
		if(global_reset_detect_info_addr == NULL)
		{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
			printk(KERN_ERR "rainbow_reset_detect_kernel:addr ioremap_nocache fail \n");
#endif
			return NULL;
		}
		else
		{
			printk(KERN_ERR "rainbow_reset_detect_kernel:addr %x ioremap to %x\n",RAINBOW_RESET_DETECT_ADDR,global_reset_detect_info_addr);
			return global_reset_detect_info_addr;
		}
	}
	return global_reset_detect_info_addr;
}

static unsigned int rainbow_reset_detect_get_flag(unsigned int flag)
{
	reset_detect_info *fdump_header = rainbow_reset_detect_info_addr_map();
	if(fdump_header == NULL)
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:get flag fail,global header NULL \n");
#endif
		return;
	}

	if((fdump_header->reset_reason_str_ready_flag)&flag == flag)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

static unsigned int rainbow_reset_detect_set_flag(unsigned int flag)
{
	reset_detect_info *fdump_header = rainbow_reset_detect_info_addr_map();
	if(fdump_header == NULL)
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:set flag fail,global header NULL \n");
#endif
		return 0;
	}

	fdump_header->reset_reason_str_ready_flag |= flag;
	return 1;
}

void rainbow_reset_detect_m_reason_set(uint32_t reason)
{
	reset_detect_info *fdump_header = rainbow_reset_detect_info_addr_map();
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:mreason set start\n");
#endif
	if(fdump_header == NULL)
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:global addr is NULL\n");
#endif
		return;
	}
	if(fdump_header->reset_reason_m_magic == FD_M_UNKOWN)
	{
		fdump_header->reset_reason_m_magic = reason;
		printk(KERN_ERR "rainbow_reset_detect_kernel:mreason set %d \n",reason);
	}
	else
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:mreason have recount\n");
#endif
	}
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:mreason set end\n");
#endif
	return;
}
EXPORT_SYMBOL(rainbow_reset_detect_m_reason_set);

void rainbow_reset_detect_s_reason_set(uint32_t reason)
{
	reset_detect_info *fdump_header = rainbow_reset_detect_info_addr_map();
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:sreason set start\n");
#endif

	if(fdump_header == NULL)
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:global addr is NULL\n");
#endif
		return;
	}
	
	if(fdump_header->reset_reason_s_magic == FD_S_MAX)
	{
		fdump_header->reset_reason_s_magic = reason;
		printk(KERN_ERR "rainbow_reset_detect_kernel:sreason set %d \n",reason);
	}
	else
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:sreason have recount\n");
#endif
	}
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:sreason set end\n");
#endif

	return;
}
EXPORT_SYMBOL(rainbow_reset_detect_s_reason_set);

void rainbow_reset_detect_s_reason_str_set(char *reason_s_info)
{
	reset_detect_info *fdump_header = rainbow_reset_detect_info_addr_map();
	unsigned int str_tmp_len = strlen(reason_s_info);
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:sreason string set start\n");
#endif
	if(fdump_header == NULL || reason_s_info == NULL)
	{
		return;
	}
	if(rainbow_reset_detect_get_flag(FD_S_REASON_STR_FLAG))
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel: sreason string have recount skip\n");
#endif
		return;
	}
#ifdef CONFIG_ARM64
	memset_io(fdump_header->reset_s_reason,'\0',RESET_DETECT_REASON_STR_MAX);
#else
	memset(fdump_header->reset_s_reason,'\0',RESET_DETECT_REASON_STR_MAX);
#endif
	if(str_tmp_len>(RESET_DETECT_REASON_STR_MAX-1))
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:sreason string length too long\n");
#endif
	}
	else
	{
#ifdef CONFIG_ARM64
		memcpy_toio(fdump_header->reset_s_reason,reason_s_info,str_tmp_len);
		fdump_header->reset_s_reason[str_tmp_len]='\0';
#else
		strlcpy(fdump_header->reset_s_reason, reason_s_info,RESET_DETECT_REASON_STR_MAX);
#endif
		rainbow_reset_detect_set_flag(FD_S_REASON_STR_FLAG);
		printk(KERN_ERR "rainbow_reset_detect_kernel:sreason string set %s\n",fdump_header->reset_s_reason);
	}
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:sreason string set end\n");
#endif
}
EXPORT_SYMBOL(rainbow_reset_detect_s_reason_str_set);

void rainbow_reset_detect_s_reason_str_set_format(const char *fmt, ...)
{
	char buf[RESET_DETECT_REASON_STR_MAX]={0};
	int err;
	va_list ap;
	if(fmt == NULL)
	{
		return;
	}
	va_start(ap, fmt);
	err = vscnprintf(buf, RESET_DETECT_REASON_STR_MAX, fmt, ap);
	va_end(ap);
	if(err<0)
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:sreason string format set fail in vsnprintf\n");
#endif
		return;
	}
	rainbow_reset_detect_s_reason_str_set(buf);
}
EXPORT_SYMBOL(rainbow_reset_detect_s_reason_str_set_format);

void rainbow_reset_detect_reason_info_str_set(char *reason_s_info)
{
	reset_detect_info *fdump_header = rainbow_reset_detect_info_addr_map();
	unsigned int str_tmp_len = strlen(reason_s_info);
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:reason_info string set start\n");
#endif
	if(fdump_header == NULL || reason_s_info == NULL)
	{
		return;
	}
	if(rainbow_reset_detect_get_flag(FD_INFO_REASON_STR_FLAG))
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:reason_info string have skip\n");
#endif
		return;
	}
#ifdef CONFIG_ARM64
	memset_io(fdump_header->reset_reason_info,'\0',RESET_DETECT_REASON_STR_MAX);
#else
	memset(fdump_header->reset_reason_info,'\0',RESET_DETECT_REASON_STR_MAX);
#endif
	if(str_tmp_len>(RESET_DETECT_REASON_STR_MAX-1))
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel: reason_info string length too long\n");
#endif
	}
	else
	{
#ifdef CONFIG_ARM64
		memcpy_toio(fdump_header->reset_reason_info,reason_s_info,str_tmp_len);
		fdump_header->reset_reason_info[str_tmp_len]='\0';
#else
		strlcpy(fdump_header->reset_reason_info, reason_s_info,RESET_DETECT_REASON_STR_MAX);
#endif
		rainbow_reset_detect_set_flag(FD_INFO_REASON_STR_FLAG);
		printk(KERN_ERR "rainbow_reset_detect_kernel:reason_info string set %s\n",fdump_header->reset_reason_info);
	}
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:reason_info string set end\n");
#endif
}
EXPORT_SYMBOL(rainbow_reset_detect_reason_info_str_set);

void rainbow_reset_detect_reason_info_str_set_format(const char *fmt, ...)
{
	char buf[RESET_DETECT_REASON_STR_MAX]={0};
	int err;
	if(fmt == NULL)
	{
		return;
	}
	va_list ap;
	va_start(ap, fmt);
	err = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if(err<0)
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:reason_info string vsnprintf fail\n");
#endif
		return;
	}
	rainbow_reset_detect_reason_info_str_set(buf);
}
EXPORT_SYMBOL(rainbow_reset_detect_reason_info_str_set_format);

void rainbow_reset_detect_reason_info_regs_kallsyms_set(const char *fmt, unsigned long addr)
{
	int err;
	char temp_reason_info_buffer[RESET_DETECT_REASON_STR_MAX]={0};
	if(fmt == NULL)
	{
		return;
	}
	char kallsyms_buffer[KSYM_SYMBOL_LEN];
	__check_printsym_format(fmt, "");
	sprint_symbol(kallsyms_buffer, (unsigned long)__builtin_extract_return_addr((void *)addr));
	err = snprintf(temp_reason_info_buffer, RESET_DETECT_REASON_STR_MAX, fmt, kallsyms_buffer);
	if(err<0)
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:reason_info kallsyms string snprintf fail\n");
#endif
		return;
	}
	rainbow_reset_detect_reason_info_str_set(temp_reason_info_buffer);
}
EXPORT_SYMBOL(rainbow_reset_detect_reason_info_regs_kallsyms_set);

void rainbow_reset_detect_show(void)
{
	if(global_reset_detect_info_addr == NULL)
	{
		printk(KERN_ERR "rainbow_reset_detect_kernel: show function fail,addr is null\n");
		return;
	}
	
	printk(KERN_ERR "rainbow_reset_detect_kernel:mreason:%d,sreason:%d,reset_reason_str_ready_flag:%d\n",global_reset_detect_info_addr->reset_reason_m_magic,global_reset_detect_info_addr->reset_reason_s_magic,global_reset_detect_info_addr->reset_reason_str_ready_flag);
}

static int __init rainbow_reset_detect_init(void)
{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:init start\n");
#endif
	if(NULL == rainbow_reset_detect_info_addr_map())
	{
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
		printk(KERN_ERR "rainbow_reset_detect_kernel:init fail\n");
#endif
		return -1;
	}
    rainbow_reset_detect_show();
#ifdef CONFIG_RAINBOW_DEBUG_MACRO
	printk(KERN_ERR "rainbow_reset_detect_kernel:init end\n");
#endif
	return 0;
}

static void __exit rainbow_reset_detect_exit(void)
{
	if(global_reset_detect_info_addr!=NULL)
	{
		iounmap((void*)global_reset_detect_info_addr);
	}
	return;
}
module_init(rainbow_reset_detect_init);
module_exit(rainbow_reset_detect_exit);
MODULE_LICENSE("GPL");