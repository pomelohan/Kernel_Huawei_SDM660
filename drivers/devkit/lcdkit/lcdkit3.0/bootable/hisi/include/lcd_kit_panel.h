#ifndef _LCD_KIT_PANEL_H_
#define _LCD_KIT_PANEL_H_
#include "hisi_fb.h"

/*
*product id
*/
#define PRODUCT_ALPS	1002

/*
*panel compatible
*/
#define PANEL_JDI_NT36860C "jdi_2lane_nt36860_5p88_1440P_cmd"

/*
*struct
*/
struct lcd_kit_panel_ops {
	int (*lcd_kit_get_tp_color)(struct hisi_fb_data_type* hisifd);
};

struct lcd_kit_panel_map {
	uint32_t product_id;
	char *compatible;
	int (*callback)(void);
};

/*
*function declare
*/
struct lcd_kit_panel_ops *lcd_kit_panel_get_ops(void);
int lcd_kit_panel_init(void);
int lcd_kit_panel_ops_register(struct lcd_kit_panel_ops * ops);
int lcd_kit_panel_ops_unregister(struct lcd_kit_panel_ops * ops);
#endif
