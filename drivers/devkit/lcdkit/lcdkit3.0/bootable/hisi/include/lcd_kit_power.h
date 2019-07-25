#ifndef _LCD_KIT_POWER_H_
#define _LCD_KIT_POWER_H_
#include "lcd_kit_utils.h"
/********************************************************************
*macro
********************************************************************/
#define GPIO_NAME "gpio"
#define ENABLE 1
#define DISABLE 0

enum gpio_operator {
	GPIO_REQ,
	GPIO_RELEASE,
	GPIO_HIGH,
	GPIO_LOW,
};

/********************************************************************
*variable
********************************************************************/

/********************************************************************
*struct
********************************************************************/
struct gpio_power_arra {
	enum gpio_operator oper;
	int num;
	struct gpio_desc* cm;
};

struct event_callback {
	uint32_t    event;
	int (*func)(void* data);
};

int lcd_kit_vci_power_ctrl(int enable);
int lcd_kit_iovcc_power_ctrl(int enable);
int lcd_kit_vsp_power_ctrl(int enable);
int lcd_kit_vsn_power_ctrl(int enable);
int lcd_kit_reset_power_ctrl(int enable);
int lcd_kit_bl_power_ctrl(int enable);
void lcd_kit_gpio_tx(uint32_t type, uint32_t op);
int lcd_kit_power_init(void);
#endif
