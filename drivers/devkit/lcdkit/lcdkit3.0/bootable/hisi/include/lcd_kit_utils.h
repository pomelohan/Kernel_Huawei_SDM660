#ifndef __LCD_KIT_UTILS_H_
#define __LCD_KIT_UTILS_H_
#include "lcd_kit_common.h"
#include "hisi_mipi_dsi.h"
#include "lcd_kit_adapt.h"
#include "lcd_kit_panel.h"

#define DTS_LCD_PANEL_TYPE  "/huawei,lcd_panel"
#define LCD_KIT_DEFAULT_PANEL   "/huawei,lcd_config/lcd_kit_default_auo_otm1901a_5p2_1080p_video_default"
#define LCD_KIT_DEFAULT_COMPATIBLE   "auo_otm1901a_5p2_1080p_video_default"
#define LCD_DDIC_INFO_LEN 64

#define REG61H_VALUE_FOR_RGBW 3800 // get the same brightness as in fastboot when enter kernel at the first time

struct lcd_kit_quickly_sleep_out_desc {
	uint32_t support;
	uint32_t interval;
};

struct lcd_kit_tp_color_desc {
	uint32_t support;
	struct lcd_kit_dsi_panel_cmds cmds;
};

struct lcd_kit_snd_disp {
	u32 support;
	struct lcd_kit_dsi_panel_cmds on_cmds;
	struct lcd_kit_dsi_panel_cmds off_cmds;
};

struct lcd_kit_rgbw {
	u32 support;
	struct lcd_kit_dsi_panel_cmds backlight_cmds;
};
int lcd_kit_get_tp_color(struct hisi_fb_data_type* hisifd);
int lcd_kit_adapt_init(void);
uint32_t lcd_kit_get_backlight_type(struct hisi_panel_info* pinfo);
int lcd_kit_utils_init(struct hisi_panel_info* pinfo);
int lcd_kit_dsi_fifo_is_full(uint32_t dsi_base);
void lcd_kit_read_power_status(struct hisi_fb_data_type* hisifd);
int lcd_kit_pwm_set_backlight(struct hisi_fb_data_type *hisifd, uint32_t bl_level);
uint32_t lcd_kit_blpwm_set_backlight(struct hisi_fb_data_type* hisifd, uint32_t bl_level);
int lcd_kit_sh_blpwm_set_backlight(struct hisi_fb_data_type *hisifd, uint32_t bl_level);
int lcd_kit_set_mipi_backlight(struct hisi_fb_data_type* hisifd, uint32_t bl_level);
char* lcd_kit_get_compatible(uint32_t product_id, uint32_t lcd_id);
char* lcd_kit_get_lcd_name(uint32_t product_id, uint32_t lcd_id);
int lcd_kit_dsi_cmds_tx(void* hld, struct lcd_kit_dsi_panel_cmds* cmds);
int lcd_kit_dsi_cmds_rx(void* hld, uint8_t* out, struct lcd_kit_dsi_panel_cmds* cmds);
#endif
