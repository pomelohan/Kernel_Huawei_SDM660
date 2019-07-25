#include <boardid.h>
#include "hisi_fb.h"
#include "lcd_kit_panels.h"
#include "lcd_kit_disp.h"
#include <oeminfo_ops.h>
#include "lcd_kit_effect.h"
#include "lcd_kit_power.h"
#include "lcd_kit_utils.h"

static struct lcd_kit_disp_desc g_lcd_kit_disp_info;
static struct hisi_panel_info lcd_pinfo = {0};
struct lcd_kit_disp_desc *lcd_kit_get_disp_info(void)
{
	return &g_lcd_kit_disp_info;
}

static int lcd_kit_panel_on(struct hisi_fb_panel_data* pdata, struct hisi_fb_data_type* hisifd)
{
	struct hisi_panel_info* pinfo = NULL;
	int ret = LCD_KIT_OK;

	if (!hisifd || !pdata) {
		LCD_KIT_ERR("hisifd or pdata is NULL!\n");
		return LCD_KIT_FAIL;
	}
	LCD_KIT_INFO("fb%d, +!\n", hisifd->index);
	pinfo = hisifd->panel_info;
	if (!pinfo) {
		LCD_KIT_ERR("panel_info is NULL!\n");
		return LCD_KIT_FAIL;
	}

	switch (pinfo->lcd_init_step) {
		case LCD_INIT_POWER_ON:
			ret = common_ops->panel_power_on(hisifd);
			pinfo->lcd_init_step = LCD_INIT_MIPI_LP_SEND_SEQUENCE;
			break;
		case LCD_INIT_MIPI_LP_SEND_SEQUENCE:
			ret = common_ops->panel_on_lp(hisifd);
			lcd_kit_get_tp_color(hisifd);
			lcd_kit_read_power_status(hisifd);
			pinfo->lcd_init_step = LCD_INIT_MIPI_HS_SEND_SEQUENCE;
			break;
		case LCD_INIT_MIPI_HS_SEND_SEQUENCE:
			ret = common_ops->panel_on_hs(hisifd);
			break;
		case LCD_INIT_NONE:
			break;
		case LCD_INIT_LDI_SEND_SEQUENCE:
			break;
		default:
			break;
	}
	LCD_KIT_INFO("fb%d, -!\n", hisifd->index);
	return ret;
}

static int lcd_kit_panel_off(struct hisi_fb_panel_data* pdata, struct hisi_fb_data_type* hisifd)
{
	struct hisi_panel_info* pinfo = NULL;
	int ret = LCD_KIT_OK;

	if (!hisifd || !pdata) {
		LCD_KIT_ERR("hisifd or pdata is NULL!\n");
		return LCD_KIT_FAIL;
	}
	LCD_KIT_INFO("fb%d, +!\n", hisifd->index);
	pinfo = hisifd->panel_info;
	if (!pinfo) {
		LCD_KIT_ERR("panel_info is NULL!\n");
		return LCD_KIT_FAIL;
	}
	switch (pinfo->lcd_uninit_step) {
		case LCD_UNINIT_MIPI_HS_SEND_SEQUENCE:
			ret = common_ops->panel_off_hs(hisifd);
			pinfo->lcd_uninit_step = LCD_UNINIT_MIPI_LP_SEND_SEQUENCE;
			break;
		case LCD_UNINIT_MIPI_LP_SEND_SEQUENCE:
			ret = common_ops->panel_off_lp(hisifd);
			pinfo->lcd_uninit_step = LCD_UNINIT_POWER_OFF;
			break;
		case LCD_UNINIT_POWER_OFF:
			ret = common_ops->panel_power_off(hisifd);
			break;
		default:
			break;
	}
	LCD_KIT_INFO("fb%d, -!\n", hisifd->index);
	return ret;
}

static int  lcd_kit_set_backlight(struct hisi_fb_panel_data* pdata,
								  struct hisi_fb_data_type* hisifd, uint32_t bl_level)
{
	uint32_t bl_type = 0;
	int ret = LCD_KIT_OK;
	struct hisi_panel_info* pinfo = NULL;

	if (!hisifd) {
		LCD_KIT_ERR("hisifd is null\n");
		return LCD_KIT_FAIL;
	}
	/*quickly sleep*/
	if (disp_info->quickly_sleep_out.support) {
		if (disp_info->quickly_sleep_out.interval> 0) {
			mdelay(disp_info->quickly_sleep_out.interval);
		}
	}
	pinfo = hisifd->panel_info;
	/*mapping bl_level from bl_max to 255 step*/
	bl_level = bl_level * pinfo->bl_max/255;
	bl_type = lcd_kit_get_backlight_type(pinfo);
	switch (bl_type) {
		case BL_SET_BY_PWM:
			ret = lcd_kit_pwm_set_backlight(hisifd, bl_level);
			break;
		case BL_SET_BY_BLPWM:
			ret = lcd_kit_blpwm_set_backlight(hisifd, bl_level);
			break;
		case BL_SET_BY_SH_BLPWM:
			ret = lcd_kit_sh_blpwm_set_backlight(hisifd, bl_level);
			break;
		case BL_SET_BY_MIPI:
			ret = lcd_kit_set_mipi_backlight(hisifd, bl_level);
			break;
		default:
			break;
	}
	LCD_KIT_INFO("bl_level = %d, bl_type = %d\n", bl_level, bl_type);
	return ret;
}

/*panel data*/
static struct hisi_fb_panel_data lcd_kit_panel_data = {
	.on             = lcd_kit_panel_on,
	.off            = lcd_kit_panel_off,
	.set_backlight  = lcd_kit_set_backlight,
	.next           = NULL,
};

static int lcd_kit_probe(struct hisi_fb_data_type* hisifd)
{
	struct hisi_panel_info* pinfo = NULL;
	int ret = LCD_KIT_OK;

	if (!hisifd) {
		LCD_KIT_ERR("hisifd is NULL!\n");
		return LCD_KIT_FAIL;
	}
	LCD_KIT_INFO(" enter\n");
	// init lcd panel info
	pinfo = &lcd_pinfo;
	memset_s(pinfo, sizeof(struct hisi_panel_info), 0, sizeof(struct hisi_panel_info));
	/*adapt init*/
	lcd_kit_adapt_init();
	/*common init*/
	if (common_ops->common_init) {
		common_ops->common_init(disp_info->compatible);
	}
	/*utils init*/
	lcd_kit_utils_init(pinfo);
	/*panel init*/
	lcd_kit_panel_init();
	/*power init*/	
	lcd_kit_power_init();
	/*panel chain*/
	hisifd->panel_info = pinfo;
	lcd_kit_panel_data.next = hisifd->panel_data;
	hisifd->panel_data = &lcd_kit_panel_data;
	/*add device*/
	hisi_fb_add_device(hisifd);
	LCD_KIT_INFO(" exit\n");
	return ret;
}

struct hisi_fb_data_type lcd_kit_hisifd = {
	.panel_probe = lcd_kit_probe,
};

static int lcd_kit_init(struct system_table* systable)
{
	int lcd_type = UNKNOWN_LCD;
	struct lcd_type_operators* lcd_type_ops = NULL;

	lcd_type_ops = get_operators(LCD_TYPE_MODULE_NAME_STR);
	if (!lcd_type_ops) {
		LCD_KIT_ERR("failed to get lcd type operator!\n");
	} else {
		lcd_type = lcd_type_ops->get_lcd_type();
		LCD_KIT_INFO("lcd_type = %d\n", lcd_type);
		if  (lcd_type == LCD_KIT) {
			LCD_KIT_INFO("lcd type is LCD_KIT.\n");
			/*init lcd id*/
			disp_info->lcd_id = lcd_type_ops->get_lcd_id();
			disp_info->product_id = lcd_type_ops->get_product_id();
			disp_info->compatible = lcd_kit_get_compatible(disp_info->product_id, disp_info->lcd_id);
			disp_info->lcd_name = lcd_kit_get_lcd_name(disp_info->product_id, disp_info->lcd_id);
			lcd_type_ops->set_lcd_panel_type(disp_info->compatible);
			lcd_type_ops->set_hisifd(&lcd_kit_hisifd);
			LCD_KIT_INFO("disp_info->lcd_id = %d, disp_info->product_id = %d,disp_info->compatible = %s, disp_info->lcd_name = %s\n",
				disp_info->lcd_id, disp_info->product_id, disp_info->compatible, disp_info->lcd_name);
		} else {
			LCD_KIT_INFO("lcd type is not LCD_KIT.\n");
		}
	}
	return LCD_KIT_OK;
}

static struct module_data lcd_kit_module_data = {
	.name = LCD_KIT_MODULE_NAME_STR,
	.level   = LCDKIT_MODULE_LEVEL,
	.init = lcd_kit_init,
};

MODULE_INIT(LCD_KIT_MODULE_NAME, lcd_kit_module_data);
