#ifndef _LCD_KIT_ADAPT_H_
#define _LCD_KIT_ADAPT_H_
#include "hisi_fb.h"
#include "libfdt_env.h"

/*print log*/
extern u32 g_lcd_kit_msg_level;
#define LCD_KIT_ERR(msg, ...)    \
		if (g_lcd_kit_msg_level >= MSG_LEVEL_ERROR)  \
			PRINT_ERROR("[LCD_KIT/E]%s: "msg, __func__, ## __VA_ARGS__)
#define LCD_KIT_WARNING(msg, ...)    \
		if (g_lcd_kit_msg_level >= MSG_LEVEL_WARNING)	\
			PRINT_ERROR("[LCD_KIT/W]%s: "msg, __func__, ## __VA_ARGS__)
#define LCD_KIT_INFO(msg, ...)    \
		if (g_lcd_kit_msg_level >= MSG_LEVEL_INFO)	\
			PRINT_ERROR("[LCD_KIT/I]%s: "msg, __func__, ## __VA_ARGS__)
#define LCD_KIT_DEBUG(msg, ...)    \
		if (g_lcd_kit_msg_level >= MSG_LEVEL_DEBUG) \
			PRINT_ERROR("[LCD_KIT/D]%s: "msg, __func__, ## __VA_ARGS__)

/*function declare*/
#endif
