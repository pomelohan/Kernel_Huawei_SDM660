#ifndef _LCD_KIT_DISP_H_
#define _LCD_KIT_DISP_H_
#include "hisi_fb.h"
#include "lcd_kit_utils.h"
#include "lcd_kit_effect.h"
#include "lcd_kit_panels.h"

/********************************************************************
*macro
********************************************************************/
#define DTS_COMP_LCD_KIT_PANEL_TYPE     "huawei,lcd_panel_type"
#define LCD_KIT_MODULE_NAME          lcd_kit
#define LCD_KIT_MODULE_NAME_STR     "lcd_kit"

struct lcd_kit_disp_desc *lcd_kit_get_disp_info(void);
#define disp_info	lcd_kit_get_disp_info()

/********************************************************************
*struct
********************************************************************/
struct lcd_kit_disp_desc {
	char* lcd_name;
	char* compatible;
	uint32_t lcd_id;
	uint32_t product_id;
	uint32_t gpio_id0;
	uint32_t gpio_id1;
	uint32_t gpio_te;
	uint32_t gpio_backlight;
	uint32_t dynamic_gamma_support;
	uint32_t dsi1_cmd_support;
	/*second display*/
	struct lcd_kit_snd_disp snd_display;
	/*quickly sleep out*/
	struct lcd_kit_quickly_sleep_out_desc quickly_sleep_out;
	/*tp color*/
	struct lcd_kit_tp_color_desc tp_color;
	/*rgbw*/
	struct lcd_kit_rgbw rgbw;
};
#endif
