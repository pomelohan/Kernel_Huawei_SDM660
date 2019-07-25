#include "lcd_kit_common.h"
#include "lcd_kit_bias.h"

/*log level*/
u32 g_lcd_kit_msg_level = MSG_LEVEL_INFO;
/*hw adapt ops*/
static struct lcd_kit_adapt_ops *g_adapt_pops = NULL;
/*power sequence*/
static struct lcd_kit_power_seq_desc g_lcd_kit_power_sequence;
/*power handle*/
static struct lcd_kit_power_desc g_lcd_kit_power_handle;
/*common info*/
static struct lcd_kit_common_desc g_lcd_kit_common_info;
struct lcd_kit_common_desc *lcd_kit_get_common_info(void)
{
	return &g_lcd_kit_common_info;
}

struct lcd_kit_power_seq_desc *lcd_kit_get_power_seq(void)
{
	return &g_lcd_kit_power_sequence;
}

struct lcd_kit_power_desc *lcd_kit_get_power_handle(void)
{
	return &g_lcd_kit_power_handle;
}

int lcd_kit_vci_power_ctrl(int enable)
{
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
    if (NULL == power_hdl->lcd_vci.buf){
		LCD_KIT_ERR("can not get lcd vci!\n");
		return LCD_KIT_FAIL;
    }
	switch (power_hdl->lcd_vci.buf[0]) {
		case GPIO_MODE:
			if (enable) {
				if (adapt_ops->gpio_enable) {
					adapt_ops->gpio_enable(LCD_KIT_VCI);
				}
			} else {
				if (adapt_ops->gpio_disable) {
					adapt_ops->gpio_disable(LCD_KIT_VCI);
				}
			}
			break;
		case REGULATOR_MODE:
			if (enable) {
				if (adapt_ops->regulator_enable) {
					adapt_ops->regulator_enable(LCD_KIT_VCI);
				}
			} else {
				if (adapt_ops->regulator_disable) {
					adapt_ops->regulator_disable(LCD_KIT_VCI);
				}
			}
			break;
        case NONE_MODE:
            LCD_KIT_DEBUG("lcd vci mode is none mode\n");
            break;
        default:
            LCD_KIT_ERR("lcd vci mode is not normal\n");
            return LCD_KIT_FAIL;
	}
	return LCD_KIT_OK;
}

int lcd_kit_iovcc_power_ctrl(int enable)
{
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
    if (NULL == power_hdl->lcd_iovcc.buf){
		LCD_KIT_ERR("can not get lcd iovcc!\n");
		return LCD_KIT_FAIL;
    }
	switch (power_hdl->lcd_iovcc.buf[0]) {
		case GPIO_MODE:
			if (enable) {
				if (adapt_ops->gpio_enable) {
					adapt_ops->gpio_enable(LCD_KIT_IOVCC);
				}
			} else {
				if (adapt_ops->gpio_disable) {
					adapt_ops->gpio_disable(LCD_KIT_IOVCC);
				}
			}
			break;
		case REGULATOR_MODE:
			if (enable) {
				if (adapt_ops->regulator_enable) {
					adapt_ops->regulator_enable(LCD_KIT_IOVCC);
				}
			} else {
				if (adapt_ops->regulator_disable) {
					adapt_ops->regulator_disable(LCD_KIT_IOVCC);
				}
			}
			break;
        case NONE_MODE:
            LCD_KIT_DEBUG("lcd iovcc mode is none mode\n");
            break;
        default:
            LCD_KIT_ERR("lcd iovcc mode is not normal\n");
            return LCD_KIT_FAIL;
	}
	return LCD_KIT_OK;
}

int lcd_kit_vdd_power_ctrl(int enable)
{
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
    if (NULL == power_hdl->lcd_vdd.buf){
		LCD_KIT_ERR("can not get lcd vdd!\n");
		return LCD_KIT_FAIL;
    }
	switch (power_hdl->lcd_vdd.buf[0]) {
		case GPIO_MODE:
			if (enable) {
				if (adapt_ops->gpio_enable) {
					adapt_ops->gpio_enable(LCD_KIT_VDD);
				}
			} else {
				if (adapt_ops->gpio_disable) {
					adapt_ops->gpio_disable(LCD_KIT_VDD);
				}
			}
			break;
		case REGULATOR_MODE:
			if (enable) {
				if (adapt_ops->regulator_enable) {
					adapt_ops->regulator_enable(LCD_KIT_VDD);
				}
			} else {
				if (adapt_ops->regulator_disable) {
					adapt_ops->regulator_disable(LCD_KIT_VDD);
				}
			}
			break;
        case NONE_MODE:
            LCD_KIT_DEBUG("lcd vdd mode is none mode\n");
            break;
        default:
            LCD_KIT_ERR("lcd vdd mode is not normal\n");
            return LCD_KIT_FAIL;
	}
	return LCD_KIT_OK;
}

int lcd_kit_vsp_power_ctrl(int enable)
{
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
    if (NULL == power_hdl->lcd_vsp.buf){
		LCD_KIT_ERR("can not get lcd vsp!\n");
		return LCD_KIT_FAIL;
    }
	switch (power_hdl->lcd_vsp.buf[0]) {
		case GPIO_MODE:
			if (enable) {
				if (adapt_ops->gpio_enable) {
					adapt_ops->gpio_enable(LCD_KIT_VSP);
				}
			} else {
				if (adapt_ops->gpio_disable) {
					adapt_ops->gpio_disable(LCD_KIT_VSP);
				}
			}
			break;
		case REGULATOR_MODE:
			if (enable) {
				if (adapt_ops->regulator_enable) {
					adapt_ops->regulator_enable(LCD_KIT_VSP);
				}
			} else {
				if (adapt_ops->regulator_disable) {
					adapt_ops->regulator_disable(LCD_KIT_VSP);
				}
			}
			break;
        case NONE_MODE:
            LCD_KIT_DEBUG("lcd vsp mode is none mode\n");
            break;
        default:
            LCD_KIT_ERR("lcd vsp mode is not normal\n");
            return LCD_KIT_FAIL;
	}
	return LCD_KIT_OK;
}

int lcd_kit_vsn_power_ctrl(int enable)
{
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
    if (NULL == power_hdl->lcd_vsn.buf){
		LCD_KIT_ERR("can not get lcd vsn!\n");
		return LCD_KIT_FAIL;
    }
	switch (power_hdl->lcd_vsn.buf[0]) {
		case GPIO_MODE:
			if (enable) {
				if (adapt_ops->gpio_enable) {
					adapt_ops->gpio_enable(LCD_KIT_VSN);
				}
			} else {
				if (adapt_ops->gpio_disable) {
					adapt_ops->gpio_disable(LCD_KIT_VSN);
				}
			}
			break;
		case REGULATOR_MODE:
			if (enable) {
				if (adapt_ops->regulator_enable) {
					adapt_ops->regulator_enable(LCD_KIT_VSN);
				}
			} else {
				if (adapt_ops->regulator_disable) {
					adapt_ops->regulator_disable(LCD_KIT_VSN);
				}
			}
			break;
        case NONE_MODE:
            LCD_KIT_DEBUG("lcd vsn mode is none mode\n");
            break;
        default:
            LCD_KIT_ERR("lcd vsn mode is not normal\n");
            return LCD_KIT_FAIL;
	}
	return LCD_KIT_OK;
}

int lcd_kit_set_bias_voltage(void)
{
	struct lcd_kit_bias_ops *bias_ops = NULL;
	int ret = LCD_KIT_OK;

	bias_ops = lcd_kit_get_bias_ops();
	if (!bias_ops) {
		LCD_KIT_ERR("can not get bias_ops!\n");
		return LCD_KIT_FAIL;
	}
	/*set bias voltage*/
	if (bias_ops->set_bias_voltage) {
		ret = bias_ops->set_bias_voltage(power_hdl->lcd_vsp.buf[2], power_hdl->lcd_vsn.buf[2]);
	}
	return ret;
}

int lcd_kit_reset_power_ctrl(int enable)
{
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
	if (NULL == power_hdl->lcd_rst.buf){
		LCD_KIT_ERR("can not get lcd reset!\n");
		return LCD_KIT_FAIL;
    }
	switch (power_hdl->lcd_rst.buf[0]) {
		case GPIO_MODE:
			if (enable) {
				if (adapt_ops->gpio_enable) {
					adapt_ops->gpio_enable(LCD_KIT_RST);
				}
			} else {
				if (adapt_ops->gpio_disable) {
					adapt_ops->gpio_disable(LCD_KIT_RST);
				}
			}
			break;
		default:
			LCD_KIT_ERR("not support mode\n");
			break;
	}
	return LCD_KIT_OK;
}

int lcd_kit_tp_reset_power_ctrl(int enable)
{
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
	if (NULL == power_hdl->tp_rst.buf){
		LCD_KIT_ERR("can not get lcd reset!\n");
		return LCD_KIT_FAIL;
    }
	switch (power_hdl->tp_rst.buf[0]) {
		case GPIO_MODE:
			/*judge gpio is valid*/
			if (power_hdl->tp_rst.buf[1] > 0) {
				if (enable) {
					if (adapt_ops->gpio_enable) {
						adapt_ops->gpio_enable(LCD_KIT_TP_RST);
					}
				} else {
					if (adapt_ops->gpio_disable) {
						adapt_ops->gpio_disable(LCD_KIT_TP_RST);
					}
				}
			}
			break;
		default:
			LCD_KIT_ERR("not support mode\n");
			break;
	}
	return LCD_KIT_OK;
}

static int lcd_kit_on_cmds(void* hld)
{
	int ret = LCD_KIT_OK;
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
	if (adapt_ops->mipi_tx) {
		ret = adapt_ops->mipi_tx(hld, &common_info->panel_on_cmds);
		if (ret) {
			LCD_KIT_ERR("send panel on cmds error\n");
		}
		if (common_info->effect_on.support) {
			ret = adapt_ops->mipi_tx(hld, &common_info->effect_on.cmds);
			if (ret) {
				LCD_KIT_ERR("send effect on cmds error\n");
			}
		}
	}
	return ret;
}

static int lcd_kit_off_cmds(void* hld)
{
	int ret = LCD_KIT_OK;
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
	if (adapt_ops->mipi_tx) {
		ret = adapt_ops->mipi_tx(hld, &common_info->panel_off_cmds);
	}
	return ret;
}

int lcd_kit_panel_cmd_ctrl(void* hld, int enable)
{
	if (enable) {
		return lcd_kit_on_cmds(hld);
	} else {
		return lcd_kit_off_cmds(hld);
	}
}


int lcd_kit_event_handler(void* hld, uint32_t event, uint32_t data, uint32_t delay)
{
	int ret = LCD_KIT_OK;

	LCD_KIT_INFO("event = 0x%x, data = 0x%x, delay = %d\n", event, data, delay);
	switch (event) {
		case EVENT_VCI:
		{
			ret = lcd_kit_vci_power_ctrl(data);
			break;
		}
		case EVENT_IOVCC:
		{
			ret = lcd_kit_iovcc_power_ctrl(data);
			break;
		}
		case EVENT_VSP:
		{
			ret = lcd_kit_vsp_power_ctrl(data);
			break;
		}
		case EVENT_VSN:
		{
			ret = lcd_kit_vsn_power_ctrl(data);
			/*set biase voltge*/
			lcd_kit_set_bias_voltage();
			break;
		}
		case EVENT_RESET:
		{
			ret = lcd_kit_reset_power_ctrl(data);
			break;
		}
		case EVENT_MIPI:
		{
			ret = lcd_kit_panel_cmd_ctrl(hld, data);
			break;
		}
		case EVENT_EARLY_TS:
		case EVENT_LATER_TS:
		{
			ret = lcd_kit_tp_reset_power_ctrl(data);
			break;
		}
		case EVENT_VDD:
		{
			ret = lcd_kit_vdd_power_ctrl(data);
			break;
		}
		case EVENT_NONE:
		{
			LCD_KIT_INFO("none event\n");
			break;
		}
		default:
		{
			LCD_KIT_ERR("event not exist\n");
			ret = LCD_KIT_FAIL;
			break;
		}
	}
	if (delay > 0) {
		mdelay(delay);
	}
	return ret;
}

int lcd_kit_panel_power_on(void *hld)
{
	int i = 0;
	int ret = LCD_KIT_OK;
	struct lcd_kit_array_data *pevent = NULL;

	pevent = power_seq->power_on_seq.arry_data;
	for (i = 0; i < power_seq->power_on_seq.cnt; i++) {
		if (!pevent || !pevent->buf) {
			LCD_KIT_ERR("pevent is null!\n");
			return LCD_KIT_FAIL;
		}
		ret = lcd_kit_event_handler(hld, pevent->buf[0], pevent->buf[1], pevent->buf[2]);
		if (ret) {
			LCD_KIT_ERR("send event 0x%x error!\n", pevent->buf[0]);
		}
		pevent++;
	}
	return ret;
}

int lcd_kit_panel_power_off(void *hld)
{
	int i = 0;
	int ret = LCD_KIT_OK;
	struct lcd_kit_array_data* pevent = NULL;

	pevent = power_seq->power_off_seq.arry_data;
	for (i = 0; i < power_seq->power_off_seq.cnt; i++) {
		if (!pevent || !pevent->buf) {
			LCD_KIT_ERR("pevent is null!\n");
			return LCD_KIT_FAIL;
		}
		ret = lcd_kit_event_handler(hld, pevent->buf[0], pevent->buf[1], pevent->buf[2]);
		if (ret) {
			LCD_KIT_ERR("send event 0x%x error!\n", pevent->buf[0]);
		}
		pevent++;
	}
	return ret;
}

int lcd_kit_panel_on_lp(void *hld)
{
	int i = 0;
	int ret = LCD_KIT_OK;
	struct lcd_kit_array_data* pevent = NULL;

	pevent = power_seq->panel_on_lp_seq.arry_data;
	for (i = 0; i < power_seq->panel_on_lp_seq.cnt; i++) {
		if (!pevent || !pevent->buf) {
			LCD_KIT_ERR("pevent is null!\n");
			return LCD_KIT_FAIL;
		}
		ret = lcd_kit_event_handler(hld, pevent->buf[0], pevent->buf[1], pevent->buf[2]);
		if (ret) {
			LCD_KIT_ERR("send event 0x%x error!\n", pevent->buf[0]);
		}
		pevent++;
	}
	return ret;
}

int lcd_kit_panel_on_hs(void *hld)
{
	int i = 0;
	int ret = LCD_KIT_OK;
	struct lcd_kit_array_data* pevent = NULL;

	pevent = power_seq->panel_on_hs_seq.arry_data;
	for (i = 0; i < power_seq->panel_on_hs_seq.cnt; i++) {
		if (!pevent || !pevent->buf) {
			LCD_KIT_ERR("pevent is null!\n");
			return LCD_KIT_FAIL;
		}
		ret = lcd_kit_event_handler(hld, pevent->buf[0], pevent->buf[1], pevent->buf[2]);
		if (ret) {
			LCD_KIT_ERR("send event 0x%x error!\n", pevent->buf[0]);
		}
		pevent++;
	}
	return ret;
}

int lcd_kit_panel_off_hs(void *hld)
{
	int i = 0;
	int ret = LCD_KIT_OK;
	struct lcd_kit_array_data* pevent = NULL;

	pevent = power_seq->panel_off_hs_seq.arry_data;
	for (i = 0; i < power_seq->panel_off_hs_seq.cnt; i++) {
		if (!pevent || !pevent->buf) {
			LCD_KIT_ERR("pevent is null!\n");
			return LCD_KIT_FAIL;
		}
		ret = lcd_kit_event_handler(hld, pevent->buf[0], pevent->buf[1], pevent->buf[2]);
		if (ret) {
			LCD_KIT_ERR("send event 0x%x error!\n", pevent->buf[0]);
		}
		pevent++;
	}
	return ret;
}

int lcd_kit_panel_off_lp(void *hld)
{
	int i = 0;
	int ret = LCD_KIT_OK;
	struct lcd_kit_array_data* pevent = NULL;

	pevent = power_seq->panel_off_lp_seq.arry_data;
	for (i = 0; i < power_seq->panel_off_lp_seq.cnt; i++) {
		if (!pevent || !pevent->buf) {
			LCD_KIT_ERR("pevent is null!\n");
			return LCD_KIT_FAIL;
		}
		ret = lcd_kit_event_handler(hld, pevent->buf[0], pevent->buf[1], pevent->buf[2]);
		if (ret) {
			LCD_KIT_ERR("send event 0x%x error!\n", pevent->buf[0]);
		}
		pevent++;
	}
	return ret;
}

int lcd_kit_mipi_set_backlight(void* hld, u32 bl_level)
{
	struct lcd_kit_adapt_ops* adapt_ops = NULL;

	adapt_ops = lcd_kit_get_adapt_ops();
	if (!adapt_ops) {
		LCD_KIT_ERR("can not get adapt_ops!\n");
		return LCD_KIT_FAIL;
	}
	if (bl_level > common_info->backlight.bl_max) {
		bl_level = common_info->backlight.bl_max;
	}
	if ((bl_level < common_info->backlight.bl_min) && bl_level) {
		bl_level = common_info->backlight.bl_min;
	}
	switch(common_info->backlight.order) {
		case BL_BIG_ENDIAN:
			if (common_info->backlight.bl_max <= 0xFF) {
				common_info->backlight.bl_cmd.cmds[0].payload[1] = bl_level;
			} else {
				common_info->backlight.bl_cmd.cmds[0].payload[1] = (bl_level >> 8) & 0xFF;
				common_info->backlight.bl_cmd.cmds[0].payload[2] = bl_level & 0xFF;
			}
			break;
		case BL_LITTLE_ENDIAN:
			if (common_info->backlight.bl_max <= 0xFF) {
				common_info->backlight.bl_cmd.cmds[0].payload[1] = bl_level;
			} else {
				common_info->backlight.bl_cmd.cmds[0].payload[1] = bl_level & 0xFF;
				common_info->backlight.bl_cmd.cmds[0].payload[2] = (bl_level >> 8) & 0xFF;
			}
			break;
		default:
			break;
	}
	return adapt_ops->mipi_tx(hld, &common_info->backlight.bl_cmd);
}

static int lcd_kit_parse_power(char* compatible)
{
	/*vci*/
	lcd_kit_parse_array(compatible, "lcd-kit,lcd-vci", &power_hdl->lcd_vci);
	/*iovcc*/
	lcd_kit_parse_array(compatible, "lcd-kit,lcd-iovcc", &power_hdl->lcd_iovcc);
	/*vsp*/
	lcd_kit_parse_array(compatible, "lcd-kit,lcd-vsp", &power_hdl->lcd_vsp);
	/*vsn*/
	lcd_kit_parse_array(compatible, "lcd-kit,lcd-vsn", &power_hdl->lcd_vsn);
	/*lcd reset*/
	lcd_kit_parse_array(compatible, "lcd-kit,lcd-reset", &power_hdl->lcd_rst);
	/*backlight*/
	lcd_kit_parse_array(compatible, "lcd-kit,lcd-backlight", &power_hdl->lcd_backlight);
	/*TE0*/
	lcd_kit_parse_array(compatible, "lcd-kit,lcd-te0", &power_hdl->lcd_te0);
	/*tp reset*/
	lcd_kit_parse_array(compatible, "lcd-kit,tp-reset", &power_hdl->tp_rst);
	/*lcd vdd*/
	lcd_kit_parse_array(compatible, "lcd-kit,lcd-vdd", &power_hdl->lcd_vdd);
	return LCD_KIT_OK;
}

static int lcd_kit_parse_power_seq(char* compatible)
{
	lcd_kit_parse_arrays(compatible, "lcd-kit,power-on-stage", &power_seq->power_on_seq, 3);
	lcd_kit_parse_arrays(compatible, "lcd-kit,lp-on-stage", &power_seq->panel_on_lp_seq, 3);
	lcd_kit_parse_arrays(compatible, "lcd-kit,hs-on-stage", &power_seq->panel_on_hs_seq, 3);
	lcd_kit_parse_arrays(compatible, "lcd-kit,power-off-stage", &power_seq->power_off_seq, 3);
	lcd_kit_parse_arrays(compatible, "lcd-kit,hs-off-stage", &power_seq->panel_off_hs_seq, 3);
	lcd_kit_parse_arrays(compatible, "lcd-kit,lp-off-stage", &power_seq->panel_off_lp_seq, 3);
	return LCD_KIT_OK;
}

static int lcd_kit_parse_common_info(char* compatible)
{
	/*panel cmds*/
	lcd_kit_parse_dcs_cmds(compatible, "lcd-kit,panel-on-cmds", &common_info->panel_on_cmds);
	lcd_kit_parse_dcs_cmds(compatible, "lcd-kit,panel-off-cmds", &common_info->panel_off_cmds);
	/*backlight*/
	lcd_kit_parse_dcs_cmds(compatible, "lcd-kit,backlight-cmds", &common_info->backlight.bl_cmd);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,backlight-order", &common_info->backlight.order, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-bl-max", &common_info->backlight.bl_max, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-bl-min", &common_info->backlight.bl_min, 0);
	return LCD_KIT_OK;
}

static int lcd_kit_parse_effect(char* compatible)
{
	/*effect on support*/
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,effect-on-support", &common_info->effect_on.support, 0);
	if (common_info->effect_on.support) {
		lcd_kit_parse_dcs_cmds(compatible, "lcd-kit,effect-on-cmds", &common_info->effect_on.cmds);
	}
	return LCD_KIT_OK;
}

int lcd_kit_common_init(char* compatible)
{
	if (!compatible) {
		LCD_KIT_ERR("compatible is null\n");
		return LCD_KIT_FAIL;
	}
	lcd_kit_parse_common_info(compatible);
	lcd_kit_parse_power_seq(compatible);
	lcd_kit_parse_power(compatible);
	lcd_kit_parse_effect(compatible);
	return LCD_KIT_OK;
}

int lcd_kit_adapt_register(struct lcd_kit_adapt_ops* ops)
{
	if (g_adapt_pops) {
		LCD_KIT_ERR("g_adapt_pops has already been registered!\n");
		return LCD_KIT_FAIL;
	}
	g_adapt_pops = ops;
	LCD_KIT_INFO("g_adapt_pops register success!\n");
	return LCD_KIT_OK;
}

int lcd_kit_adapt_unregister(struct lcd_kit_adapt_ops* ops)
{
	if (g_adapt_pops == ops) {
		g_adapt_pops = NULL;
		LCD_KIT_INFO("g_adapt_pops unregister success!\n");
		return LCD_KIT_OK;
	}
	LCD_KIT_ERR("g_adapt_pops unregister fail!\n");
	return LCD_KIT_FAIL;
}

struct lcd_kit_adapt_ops* lcd_kit_get_adapt_ops(void)
{
	return g_adapt_pops;
}

/*common ops*/
struct lcd_kit_common_ops g_lcd_kit_common_ops = {
	.panel_power_on = lcd_kit_panel_power_on,
	.panel_on_lp = lcd_kit_panel_on_lp,
	.panel_on_hs = lcd_kit_panel_on_hs,
	.panel_off_hs = lcd_kit_panel_off_hs,
	.panel_off_lp = lcd_kit_panel_off_lp,
	.panel_power_off = lcd_kit_panel_power_off,
	.set_mipi_backlight = lcd_kit_mipi_set_backlight,
	.common_init = lcd_kit_common_init,
};

struct lcd_kit_common_ops *lcd_kit_get_common_ops(void)
{
	return &g_lcd_kit_common_ops;
}
