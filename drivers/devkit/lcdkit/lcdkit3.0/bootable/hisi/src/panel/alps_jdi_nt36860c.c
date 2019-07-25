/*
*panel adapter
*product:alps
*panel:jdi-nt36860c
*/
static void alps_jdi_nt36860c_get_tp_color(struct hisi_panel_info* pinfo)
{
	LCD_KIT_INFO("-_- -_- -_-\n");
}

static struct lcd_kit_panel_ops alps_jdi_nt36860c_ops = {
	.lcd_kit_get_tp_color = NULL,
};

static int alps_jdi_nt36860c_proble(void)
{
	int ret = LCD_KIT_OK;

	ret = lcd_kit_panel_ops_register(&alps_jdi_nt36860c_ops);
	if (ret) {
		LCD_KIT_ERR("failed\n");
	}
	return ret;
}
