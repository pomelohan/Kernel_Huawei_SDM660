#include "lcd_kit_disp.h"

#if defined(FASTBOOT_DISPLAY_LOGO_KIRIN970)
static struct lcdbrightnesscoloroeminfo lcd_color_oeminfo = {0};
static struct panelid lcd_panelid = {0};
extern uint32_t g_panel_vender_id;

int lcd_kit_get_bright_rgbw_id_from_oeminfo(void)
{
	struct oeminfo_operators* oeminfo_ops = NULL;

	oeminfo_ops = get_operators(OEMINFO_MODULE_NAME_STR);
	if (!oeminfo_ops) {
		HISI_FB_ERR("get_operators error \n");
		return LCD_KIT_FAIL;
	}

	if (oeminfo_ops->get_oeminfo(OEMINFO_LCD_BRIGHT_COLOR_CALIBRATION, sizeof(struct lcdbrightnesscoloroeminfo), (char*)&lcd_color_oeminfo)) {
		HISI_FB_ERR("get bright color oeminfo  error \n");
		return LCD_KIT_FAIL;
	}

	return LCD_KIT_OK;
}

int lcd_kit_set_bright_rgbw_id_to_oeminfo(void)
{
	struct oeminfo_operators* oeminfo_ops = NULL;

	oeminfo_ops = get_operators(OEMINFO_MODULE_NAME_STR);
	if (!oeminfo_ops) {
		HISI_FB_ERR("get_operators error \n");
		return LCD_KIT_FAIL;
	}

	if (oeminfo_ops->set_oeminfo(OEMINFO_LCD_BRIGHT_COLOR_CALIBRATION, sizeof(struct lcdbrightnesscoloroeminfo), (char*)&lcd_color_oeminfo)) {
		HISI_FB_ERR("set bright color oeminfo error \n");
		return LCD_KIT_FAIL;
	}

	return LCD_KIT_OK;
}

int lcd_kit_get_panel_id_info(struct hisi_fb_data_type* hisifd)
{
	return LCD_KIT_OK;
}

unsigned long lcd_kit_get_color_mem_addr(void)
{
	return HISI_SUB_RESERVED_BRIGHTNESS_CHROMA_MEM_PHYMEM_BASE;
}

void lcd_kit_write_oeminfo_to_mem(void)
{
	unsigned long mem_addr = 0;

	mem_addr = lcd_kit_get_color_mem_addr();
	memcpy(mem_addr, &lcd_color_oeminfo, sizeof(lcd_color_oeminfo));
	return;
}

void lcd_kit_bright_rgbw_id_from_oeminfo_process(struct hisi_fb_data_type* phisifd)
{
	int ret = LCD_KIT_OK;

	if (NULL == phisifd) {
		HISI_FB_ERR("pointer is NULL \n");
		return;
	}
	ret = lcd_kit_get_panel_id_info(phisifd);
	if (ret != LCD_KIT_OK) {
		HISI_FB_ERR("read panel id from lcd failed!\n");
	}
	ret = lcd_kit_get_bright_rgbw_id_from_oeminfo();
	if (ret != LCD_KIT_OK) {
		HISI_FB_ERR("read panel id wight and color info from oeminfo failed!\n");
	}

	if (lcd_color_oeminfo.id_flag == 0) {
		HISI_FB_INFO("panel id_flag is 0\n");
		lcd_color_oeminfo.panel_id = lcd_panelid;
		lcd_color_oeminfo.id_flag = 1;
		ret = lcd_kit_set_bright_rgbw_id_to_oeminfo();
		if (ret != LCD_KIT_OK) {
			HISI_FB_ERR("write panel id wight and color info to oeminfo failed!\n");
		}
		lcd_kit_write_oeminfo_to_mem();
		return;
	} else {
		if (!memcmp(&lcd_color_oeminfo.panel_id, &lcd_panelid, sizeof(lcd_color_oeminfo.panel_id))) {
			HISI_FB_INFO("panel id is same\n");
			lcd_kit_write_oeminfo_to_mem();
			return;
		} else {
			lcd_color_oeminfo.panel_id = lcd_panelid;
			if ((lcd_color_oeminfo.panel_id.modulesn == lcd_panelid.modulesn) && (lcd_color_oeminfo.panel_id.equipid == lcd_panelid.equipid) && (lcd_color_oeminfo.panel_id.modulemanufactdate == lcd_panelid.modulemanufactdate)) {
				HISI_FB_INFO("panle id and oeminfo panel id is same\n");
				if (lcd_color_oeminfo.tc_flag == 0) {
					HISI_FB_INFO("panle id and oeminfo panel id is same, set tc_flag to true\n");
					lcd_color_oeminfo.tc_flag = 1;
				}
			} else {
				HISI_FB_INFO("panle id and oeminfo panel id is not same, set tc_flag to false\n");
				lcd_color_oeminfo.tc_flag = 0;
			}
			ret = lcd_kit_set_bright_rgbw_id_to_oeminfo();
			if (ret != LCD_KIT_OK) {
				HISI_FB_ERR("write panel id wight and color info to oeminfo failed!\n");
			}
			lcd_kit_write_oeminfo_to_mem();
			return;
		}
	}
}
#endif

#if defined (FASTBOOT_DISPLAY_LOGO_HI3660) || defined (FASTBOOT_DISPLAY_LOGO_KIRIN970) || defined (FASTBOOT_DISPLAY_LOGO_KIRIN980)
#define OEMINFO_GAMMA_DATA 114    /*OEMINFO ID used for gamma data */
#define OEMINFO_GAMMA_LEN  115    /*OEMINFO ID used fir gamma data len */

/*
 *1542 = gamma_r + gamma_g + gamma_b = (257 + 257 + 257) * sizeof(u16);
 *1542 = degamma_r + degamma_g + degamma_b = (257 + 257 +257) * sizeof(u16);
*/
#define GM_IGM_LEN (1542 + 1542)
#define GM_LUT_LEN 257

static int gamma_len = 0;
static uint16_t gamma_lut[GM_LUT_LEN * 6] = {0};

static int lcd_kit_read_gamma_from_oeminfo()
{

	struct oeminfo_operators* oeminfo_ops = NULL;

	oeminfo_ops = get_operators(OEMINFO_MODULE_NAME_STR);
	if (!oeminfo_ops) {
		HISI_FB_ERR("get_operators error \n");
		return LCD_KIT_FAIL;
	}

	if (oeminfo_ops->get_oeminfo(OEMINFO_GAMMA_LEN, 4, (char*)&gamma_len)) {
		HISI_FB_ERR("get gamma oeminfo len error, and the gamma len = %d! \n", gamma_len);
		return LCD_KIT_FAIL;
	}
	if (gamma_len != GM_IGM_LEN) {
		HISI_FB_ERR("gamma oeminfo len is not correct \n");
		return LCD_KIT_FAIL;
	}

	if (oeminfo_ops->get_oeminfo(OEMINFO_GAMMA_DATA, GM_IGM_LEN, (char*)gamma_lut)) {
		HISI_FB_ERR("get gamma oeminfo data error \n");
		return LCD_KIT_FAIL;
	}

	return LCD_KIT_OK;
}

int lcd_kit_write_gm_to_reserved_mem()
{
	int ret = LCD_KIT_OK;
	unsigned long gm_addr = 0;
	unsigned long gm_size = 0;

	gm_addr = HISI_SUB_RESERVED_LCD_GAMMA_MEM_PHYMEM_BASE;
	gm_size = HISI_SUB_RESERVED_LCD_GAMMA_MEM_PHYMEM_SIZE;

	if (gm_size < GM_IGM_LEN + 4) {
		HISI_FB_ERR("gamma mem size is not enough !\n");
		return LCD_KIT_FAIL;
	}

	ret = lcd_kit_read_gamma_from_oeminfo();
	if (ret) {
		writel(0, gm_addr);
		HISI_FB_ERR("can not get oeminfo gamma data!\n");
		return LCD_KIT_FAIL;
	}

	writel((unsigned int)GM_IGM_LEN, gm_addr);
	gm_addr += 4;
	memcpy((void*)gm_addr, gamma_lut, GM_IGM_LEN);

	return LCD_KIT_OK;
}

#endif
