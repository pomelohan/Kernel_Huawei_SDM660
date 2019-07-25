#include "lcd_kit_disp.h"
#include "lcd_kit_power.h"
#include "lcd_kit_utils.h"

static void lcd_kit_orise2x(struct hisi_panel_info* pinfo)
{
	pinfo->ifbc_cmp_dat_rev0 = 1;
	pinfo->ifbc_cmp_dat_rev1 = 0;
	pinfo->ifbc_auto_sel = 0;
}

static void lcd_kit_vesa3x_single(struct hisi_panel_info* pinfo)
{
	/* dsc parameter info */
	pinfo->vesa_dsc.bits_per_component = 8;
	pinfo->vesa_dsc.bits_per_pixel = 8;
	pinfo->vesa_dsc.initial_xmit_delay = 512;
	pinfo->vesa_dsc.first_line_bpg_offset = 12;
	pinfo->vesa_dsc.mux_word_size = 48;
	/*    DSC_CTRL */
	pinfo->vesa_dsc.block_pred_enable = 1;
	pinfo->vesa_dsc.linebuf_depth = 9;
	/* RC_PARAM3 */
	pinfo->vesa_dsc.initial_offset = 6144;
	/* FLATNESS_QP_TH */
	pinfo->vesa_dsc.flatness_min_qp = 3;
	pinfo->vesa_dsc.flatness_max_qp = 12;
	/* DSC_PARAM4 */
	pinfo->vesa_dsc.rc_edge_factor = 0x6;
	pinfo->vesa_dsc.rc_model_size = 8192;
	/* DSC_RC_PARAM5: 0x330b0b */
	pinfo->vesa_dsc.rc_tgt_offset_lo = (0x330b0b >> 20) & 0xF;
	pinfo->vesa_dsc.rc_tgt_offset_hi = (0x330b0b >> 16) & 0xF;
	pinfo->vesa_dsc.rc_quant_incr_limit1 = (0x330b0b >> 8) & 0x1F;
	pinfo->vesa_dsc.rc_quant_incr_limit0 = (0x330b0b >> 0) & 0x1F;
	/* DSC_RC_BUF_THRESH0: 0xe1c2a38 */
	pinfo->vesa_dsc.rc_buf_thresh0 = (0xe1c2a38 >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh1 = (0xe1c2a38 >> 16) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh2 = (0xe1c2a38 >> 8) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh3 = (0xe1c2a38 >> 0) & 0xFF;
	/* DSC_RC_BUF_THRESH1: 0x46546269 */
	pinfo->vesa_dsc.rc_buf_thresh4 = (0x46546269 >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh5 = (0x46546269 >> 16) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh6 = (0x46546269 >> 8) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh7 = (0x46546269 >> 0) & 0xFF;
	/* DSC_RC_BUF_THRESH2: 0x7077797b */
	pinfo->vesa_dsc.rc_buf_thresh8 = (0x7077797b >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh9 = (0x7077797b >> 16) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh10 = (0x7077797b >> 8) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh11 = (0x7077797b >> 0) & 0xFF;
	/* DSC_RC_BUF_THRESH3: 0x7d7e0000 */
	pinfo->vesa_dsc.rc_buf_thresh12 = (0x7d7e0000 >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh13 = (0x7d7e0000 >> 16) & 0xFF;
	/* DSC_RC_RANGE_PARAM0: 0x1020100 */
	pinfo->vesa_dsc.range_min_qp0 = (0x1020100 >> 27) & 0x1F; //lint !e572
	pinfo->vesa_dsc.range_max_qp0 = (0x1020100 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset0 = (0x1020100 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp1 = (0x1020100 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp1 = (0x1020100 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset1 = (0x1020100 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM1: 0x94009be */
	pinfo->vesa_dsc.range_min_qp2 = (0x94009be >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp2 = (0x94009be >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset2 = (0x94009be >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp3 = (0x94009be >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp3 = (0x94009be >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset3 = (0x94009be >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM2, 0x19fc19fa */
	pinfo->vesa_dsc.range_min_qp4 = (0x19fc19fa >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp4 = (0x19fc19fa >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset4 = (0x19fc19fa >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp5 = (0x19fc19fa >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp5 = (0x19fc19fa >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset5 = (0x19fc19fa >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM3, 0x19f81a38 */
	pinfo->vesa_dsc.range_min_qp6 = (0x19f81a38 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp6 = (0x19f81a38 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset6 = (0x19f81a38 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp7 = (0x19f81a38 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp7 = (0x19f81a38 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset7 = (0x19f81a38 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM4, 0x1a781ab6 */
	pinfo->vesa_dsc.range_min_qp8 = (0x1a781ab6 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp8 = (0x1a781ab6 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset8 = (0x1a781ab6 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp9 = (0x1a781ab6 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp9 = (0x1a781ab6 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset9 = (0x1a781ab6 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM5, 0x2af62b34 */
	pinfo->vesa_dsc.range_min_qp10 = (0x2af62b34 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp10 = (0x2af62b34 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset10 = (0x2af62b34 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp11 = (0x2af62b34 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp11 = (0x2af62b34 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset11 = (0x2af62b34 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM6, 0x2b743b74 */
	pinfo->vesa_dsc.range_min_qp12 = (0x2b743b74 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp12 = (0x2b743b74 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset12 = (0x2b743b74 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp13 = (0x2b743b74 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp13 = (0x2b743b74 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset13 = (0x2b743b74 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM7, 0x6bf40000 */
	pinfo->vesa_dsc.range_min_qp14 = (0x6bf40000 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp14 = (0x6bf40000 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset14 = (0x6bf40000 >> 16) & 0x3F;
}

static void lcd_kit_vesa3x_dual(struct hisi_panel_info* pinfo)
{
	pinfo->vesa_dsc.bits_per_component = 8;
	pinfo->vesa_dsc.linebuf_depth = 9;
	pinfo->vesa_dsc.bits_per_pixel = 8;
	pinfo->vesa_dsc.initial_xmit_delay = 512;
	pinfo->vesa_dsc.first_line_bpg_offset = 12;
	pinfo->vesa_dsc.mux_word_size = 48;
	/* DSC_CTRL */
	pinfo->vesa_dsc.block_pred_enable = 1;//0;
	/* RC_PARAM3 */
	pinfo->vesa_dsc.initial_offset = 6144;
	/* FLATNESS_QP_TH */
	pinfo->vesa_dsc.flatness_min_qp = 3;
	pinfo->vesa_dsc.flatness_max_qp = 12;
	/* DSC_PARAM4 */
	pinfo->vesa_dsc.rc_edge_factor = 0x6;
	pinfo->vesa_dsc.rc_model_size = 8192;
	/* DSC_RC_PARAM5: 0x330b0b */
	pinfo->vesa_dsc.rc_tgt_offset_lo = (0x330b0b >> 20) & 0xF;
	pinfo->vesa_dsc.rc_tgt_offset_hi = (0x330b0b >> 16) & 0xF;
	pinfo->vesa_dsc.rc_quant_incr_limit1 = (0x330b0b >> 8) & 0x1F;
	pinfo->vesa_dsc.rc_quant_incr_limit0 = (0x330b0b >> 0) & 0x1F;
	/* DSC_RC_BUF_THRESH0: 0xe1c2a38 */
	pinfo->vesa_dsc.rc_buf_thresh0 = (0xe1c2a38 >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh1 = (0xe1c2a38 >> 16) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh2 = (0xe1c2a38 >> 8) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh3 = (0xe1c2a38 >> 0) & 0xFF;
	/* DSC_RC_BUF_THRESH1: 0x46546269 */
	pinfo->vesa_dsc.rc_buf_thresh4 = (0x46546269 >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh5 = (0x46546269 >> 16) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh6 = (0x46546269 >> 8) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh7 = (0x46546269 >> 0) & 0xFF;
	/* DSC_RC_BUF_THRESH2: 0x7077797b */
	pinfo->vesa_dsc.rc_buf_thresh8 = (0x7077797b >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh9 = (0x7077797b >> 16) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh10 = (0x7077797b >> 8) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh11 = (0x7077797b >> 0) & 0xFF;
	/* DSC_RC_BUF_THRESH3: 0x7d7e0000 */
	pinfo->vesa_dsc.rc_buf_thresh12 = (0x7d7e0000 >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh13 = (0x7d7e0000 >> 16) & 0xFF;
	/* DSC_RC_RANGE_PARAM0: 0x1020100 */
	pinfo->vesa_dsc.range_min_qp0 = (0x1020100 >> 27) & 0x1F; //lint !e572
	pinfo->vesa_dsc.range_max_qp0 = (0x1020100 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset0 = (0x1020100 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp1 = (0x1020100 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp1 = (0x1020100 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset1 = (0x1020100 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM1: 0x94009be */
	pinfo->vesa_dsc.range_min_qp2 = (0x94009be >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp2 = (0x94009be >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset2 = (0x94009be >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp3 = (0x94009be >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp3 = (0x94009be >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset3 = (0x94009be >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM2, 0x19fc19fa */
	pinfo->vesa_dsc.range_min_qp4 = (0x19fc19fa >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp4 = (0x19fc19fa >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset4 = (0x19fc19fa >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp5 = (0x19fc19fa >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp5 = (0x19fc19fa >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset5 = (0x19fc19fa >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM3, 0x19f81a38 */
	pinfo->vesa_dsc.range_min_qp6 = (0x19f81a38 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp6 = (0x19f81a38 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset6 = (0x19f81a38 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp7 = (0x19f81a38 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp7 = (0x19f81a38 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset7 = (0x19f81a38 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM4, 0x1a781ab6 */
	pinfo->vesa_dsc.range_min_qp8 = (0x1a781ab6 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp8 = (0x1a781ab6 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset8 = (0x1a781ab6 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp9 = (0x1a781ab6 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp9 = (0x1a781ab6 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset9 = (0x1a781ab6 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM5, 0x2af62b34 */
	pinfo->vesa_dsc.range_min_qp10 = (0x2af62b34 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp10 = (0x2af62b34 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset10 = (0x2af62b34 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp11 = (0x2af62b34 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp11 = (0x2af62b34 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset11 = (0x2af62b34 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM6, 0x2b743b74 */
	pinfo->vesa_dsc.range_min_qp12 = (0x2b743b74 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp12 = (0x2b743b74 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset12 = (0x2b743b74 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp13 = (0x2b743b74 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp13 = (0x2b743b74 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset13 = (0x2b743b74 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM7, 0x6bf40000 */
	pinfo->vesa_dsc.range_min_qp14 = (0x6bf40000 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp14 = (0x6bf40000 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset14 = (0x6bf40000 >> 16) & 0x3F;
}

static void lcd_kit_vesa3_75x_dual(struct hisi_panel_info* pinfo)
{
	pinfo->vesa_dsc.bits_per_component = 10;
	pinfo->vesa_dsc.linebuf_depth = 11;
	pinfo->vesa_dsc.bits_per_pixel = 8;
	pinfo->vesa_dsc.initial_xmit_delay = 512;
	pinfo->vesa_dsc.first_line_bpg_offset = 12;
	pinfo->vesa_dsc.mux_word_size = 48;
	/* DSC_CTRL */
	pinfo->vesa_dsc.block_pred_enable = 1;//0;
	/* RC_PARAM3 */
	pinfo->vesa_dsc.initial_offset = 6144;
	/* FLATNESS_QP_TH */
	pinfo->vesa_dsc.flatness_min_qp = 7;
	pinfo->vesa_dsc.flatness_max_qp = 16;
	/* DSC_PARAM4 */
	pinfo->vesa_dsc.rc_edge_factor = 0x6;
	pinfo->vesa_dsc.rc_model_size = 8192;
	/* DSC_RC_PARAM5: 0x330f0f */
	pinfo->vesa_dsc.rc_tgt_offset_lo = (0x330f0f >> 20) & 0xF;
	pinfo->vesa_dsc.rc_tgt_offset_hi = (0x330f0f >> 16) & 0xF;
	pinfo->vesa_dsc.rc_quant_incr_limit1 = (0x330f0f >> 8) & 0x1F;
	pinfo->vesa_dsc.rc_quant_incr_limit0 = (0x330f0f >> 0) & 0x1F;
	/* DSC_RC_BUF_THRESH0: 0xe1c2a38 */
	pinfo->vesa_dsc.rc_buf_thresh0 = (0xe1c2a38 >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh1 = (0xe1c2a38 >> 16) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh2 = (0xe1c2a38 >> 8) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh3 = (0xe1c2a38 >> 0) & 0xFF;
	/* DSC_RC_BUF_THRESH1: 0x46546269 */
	pinfo->vesa_dsc.rc_buf_thresh4 = (0x46546269 >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh5 = (0x46546269 >> 16) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh6 = (0x46546269 >> 8) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh7 = (0x46546269 >> 0) & 0xFF;
	/* DSC_RC_BUF_THRESH2: 0x7077797b */
	pinfo->vesa_dsc.rc_buf_thresh8 = (0x7077797b >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh9 = (0x7077797b >> 16) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh10 = (0x7077797b >> 8) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh11 = (0x7077797b >> 0) & 0xFF;
	/* DSC_RC_BUF_THRESH3: 0x7d7e0000 */
	pinfo->vesa_dsc.rc_buf_thresh12 = (0x7d7e0000 >> 24) & 0xFF;
	pinfo->vesa_dsc.rc_buf_thresh13 = (0x7d7e0000 >> 16) & 0xFF;
	/* DSC_RC_RANGE_PARAM0: 0x2022200 */
	pinfo->vesa_dsc.range_min_qp0 = (0x2022200 >> 27) & 0x1F; //lint !e572
	pinfo->vesa_dsc.range_max_qp0 = (0x2022200 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset0 = (0x2022200 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp1 = (0x2022200 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp1 = (0x2022200 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset1 = (0x2022200 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM1: 0x94009be */
	pinfo->vesa_dsc.range_min_qp2 = 5;//(0x94009be >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp2 = 9;//(0x94009be >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset2 = (0x94009be >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp3 = 5;//(0x94009be >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp3 = 10;//(0x94009be >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset3 = (0x94009be >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM2, 0x19fc19fa */
	pinfo->vesa_dsc.range_min_qp4 = 7;//(0x19fc19fa >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp4 = 11;//(0x19fc19fa >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset4 = (0x19fc19fa >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp5 = 7;//(0x19fc19fa >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp5 = 11;//(0x19fc19fa >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset5 = (0x19fc19fa >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM3, 0x19f81a38 */
	pinfo->vesa_dsc.range_min_qp6 = 7;//(0x19f81a38 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp6 = 11;//(0x19f81a38 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset6 = (0x19f81a38 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp7 = 7;//(0x19f81a38 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp7 = 12;//(0x19f81a38 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset7 = (0x19f81a38 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM4, 0x1a781ab6 */
	pinfo->vesa_dsc.range_min_qp8 = 7;//(0x1a781ab6 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp8 = 13;//(0x1a781ab6 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset8 = (0x1a781ab6 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp9 = 7;//(0x1a781ab6 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp9 = 14;//(0x1a781ab6 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset9 = (0x1a781ab6 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM5, 0x2af62b34 */
	pinfo->vesa_dsc.range_min_qp10 = 9;//(0x2af62b34 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp10 = 15;//(0x2af62b34 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset10 = (0x2af62b34 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp11 = 9;//(0x2af62b34 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp11 = 16;//(0x2af62b34 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset11 = (0x2af62b34 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM6, 0x2b743b74 */
	pinfo->vesa_dsc.range_min_qp12 = 9;//(0x2b743b74 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp12 = 17;//(0x2b743b74 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset12 = (0x2b743b74 >> 16) & 0x3F;
	pinfo->vesa_dsc.range_min_qp13 = 11;//(0x2b743b74 >> 11) & 0x1F;
	pinfo->vesa_dsc.range_max_qp13 = 17;//(0x2b743b74 >> 6) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset13 = (0x2b743b74 >> 0) & 0x3F;
	/* DSC_RC_RANGE_PARAM7, 0x6bf40000 */
	pinfo->vesa_dsc.range_min_qp14 = 17;//(0x6bf40000 >> 27) & 0x1F;
	pinfo->vesa_dsc.range_max_qp14 = 19;//(0x6bf40000 >> 22) & 0x1F;
	pinfo->vesa_dsc.range_bpg_offset14 = (0x6bf40000 >> 16) & 0x3F;
}

void lcd_kit_compress_config(int mode, struct hisi_panel_info* pinfo)
{
	if (!pinfo) {
		LCD_KIT_ERR("pinfo is null\n");
		return ;
	}
	switch (mode) {
		case IFBC_TYPE_ORISE2X:
			lcd_kit_orise2x(pinfo);
			break;
		case IFBC_TYPE_VESA3X_SINGLE:
			lcd_kit_vesa3x_single(pinfo);
			break;
		case IFBC_TYPE_VESA3_75X_DUAL:
			lcd_kit_vesa3_75x_dual(pinfo);
			break;
		case IFBC_TYPE_VESA3X_DUAL:
			lcd_kit_vesa3x_dual(pinfo);
			break;
		case IFBC_TYPE_NONE:
			break;
		default:
			LCD_KIT_ERR("not support compress mode:%d\n", mode);
			break;
	}
}

int lcd_kit_dsi_fifo_is_full(uint32_t dsi_base)
{
	uint32_t pkg_status = 0;
	uint32_t phy_status = 0;
	int is_timeout = 100;

	/*read status register*/
	do {
		pkg_status = inp32(dsi_base + MIPIDSI_CMD_PKT_STATUS_OFFSET);
		phy_status = inp32(dsi_base + MIPIDSI_PHY_STATUS_OFFSET);
		if ((pkg_status & 0x2) != 0x2 && !(phy_status & 0x2)) {
			break;
		}
		udelay(100);
	} while (is_timeout-- > 0);

	if (!is_timeout) {
		LCD_KIT_ERR("mipi check full fail: \n \
						MIPIDSI_CMD_PKT_STATUS = 0x%x \n \
						MIPIDSI_PHY_STATUS = 0x%x \n \
						MIPIDSI_INT_ST1_OFFSET = 0x%x \n",
					inp32(dsi_base + MIPIDSI_CMD_PKT_STATUS_OFFSET),
					inp32(dsi_base + MIPIDSI_PHY_STATUS_OFFSET),
					inp32(dsi_base + MIPIDSI_INT_ST1_OFFSET));
		return LCD_KIT_FAIL;
	}
	return LCD_KIT_OK;
}

void lcd_kit_read_power_status(struct hisi_fb_data_type* hisifd)
{
	uint32_t status = 0;
	uint32_t try_times = 0;

	outp32(hisifd->mipi_dsi0_base + MIPIDSI_GEN_HDR_OFFSET, 0x0A06);
	status = inp32(hisifd->mipi_dsi0_base + MIPIDSI_CMD_PKT_STATUS_OFFSET);
	while (status & 0x10) {
		udelay(50);
		if (++try_times > 100) {
			try_times = 0;
			LCD_KIT_ERR("Read lcd power status timeout!\n");
			break;
		}
	
		status = inp32(hisifd->mipi_dsi0_base + MIPIDSI_CMD_PKT_STATUS_OFFSET);
	}
	status = inp32(hisifd->mipi_dsi0_base + MIPIDSI_GEN_PLD_DATA_OFFSET);
	LCD_KIT_ERR("Fastboot LCD Power State = 0x%x.\n", status);
	return ;
}

int lcd_kit_pwm_set_backlight(struct hisi_fb_data_type *hisifd, uint32_t bl_level)
{
	return hisi_pwm_set_backlight(hisifd, bl_level);
}

int lcd_kit_sh_blpwm_set_backlight(struct hisi_fb_data_type *hisifd, uint32_t bl_level)
{
	return hisi_sh_blpwm_set_backlight(hisifd, bl_level);
}

int lcd_kit_get_tp_color(struct hisi_fb_data_type* hisifd)
{
	int ret = LCD_KIT_OK;
	char read_value[2] = {0};
	struct hisi_panel_info* pinfo = NULL;

	pinfo = hisifd->panel_info;
	if (disp_info->tp_color.support) {
		ret = lcd_kit_dsi_cmds_rx(hisifd, read_value, &disp_info->tp_color.cmds);
		if (ret) {
			pinfo->tp_color = 0;
		} else {
			pinfo->tp_color = read_value[0];
		}
		LCD_KIT_INFO("tp color = %d\n", pinfo->tp_color);
	} else {
		LCD_KIT_INFO("Not support tp color\n");
	}
	return ret;
}

uint32_t lcd_kit_get_backlight_type(struct hisi_panel_info* pinfo)
{
	if (pinfo->bl_set_type & BL_SET_BY_PWM) {
		return BL_SET_BY_PWM;
	} else if (pinfo->bl_set_type & BL_SET_BY_BLPWM) {
		return BL_SET_BY_BLPWM;
	} else if (pinfo->bl_set_type & BL_SET_BY_SH_BLPWM) {
		return BL_SET_BY_SH_BLPWM;
	} else if (pinfo->bl_set_type & BL_SET_BY_MIPI) {
		return BL_SET_BY_MIPI;
	} else {
		return BL_SET_BY_NONE;
	}
}

uint32_t lcd_kit_blpwm_set_backlight(struct hisi_fb_data_type* hisifd, uint32_t bl_level)
{
	int ret = LCD_KIT_OK;
	static bool already_enable = FALSE;

	if(disp_info->rgbw.support) {
		disp_info->rgbw.backlight_cmds.cmds->payload[1]= (REG61H_VALUE_FOR_RGBW>>8)&0x0f;
		disp_info->rgbw.backlight_cmds.cmds->payload[2] = REG61H_VALUE_FOR_RGBW&0xff;
		lcd_kit_dsi_cmds_tx(hisifd, &disp_info->rgbw.backlight_cmds);
	}
	ret = hisi_blpwm_set_bl(hisifd, bl_level);

	if(power_hdl->lcd_backlight.buf[0] == REGULATOR_MODE) {
		/*enable/disable backlight*/
		if (bl_level == 0 && already_enable) {
			lcd_kit_charger_ctrl(LCD_KIT_BL, DISABLE);
			already_enable = FALSE;
		} else if (!already_enable) {
			lcd_kit_charger_ctrl(LCD_KIT_BL, ENABLE);
			already_enable = TRUE;
		}
	}
	return ret;
}

int lcd_kit_set_mipi_backlight(struct hisi_fb_data_type* hisifd, uint32_t bl_level)
{
	static bool already_enable = FALSE;
	int ret = 0;

	if (common_ops->set_mipi_backlight) {
		common_ops->set_mipi_backlight(hisifd, bl_level);
	}
	if (power_hdl->lcd_backlight.buf[0] == REGULATOR_MODE) {
		if (bl_level == 0 && already_enable) {
			ret = lcd_kit_charger_ctrl(LCD_KIT_BL, DISABLE);
			already_enable = FALSE;
		} else if (!already_enable) {
			ret = lcd_kit_charger_ctrl(LCD_KIT_BL, ENABLE);
			already_enable = TRUE;
		}
	}
	return ret;
}

char* lcd_kit_get_compatible(uint32_t product_id, uint32_t lcd_id)
{
	uint32_t i = 0;

	for (i = 0; i < ARRAY_SIZE(lcd_kit_map); ++i) {
		if ((lcd_kit_map[i].board_id == product_id) && (lcd_kit_map[i].gpio_id == lcd_id)) {
			return lcd_kit_map[i].compatible;
		}
	}
	/*use defaut panel*/
	return LCD_KIT_DEFAULT_COMPATIBLE;
}

char* lcd_kit_get_lcd_name(uint32_t product_id, uint32_t lcd_id)
{
	uint32_t i = 0;

	for (i = 0; i < ARRAY_SIZE(lcd_kit_map); ++i) {
		if ((lcd_kit_map[i].board_id == product_id) && (lcd_kit_map[i].gpio_id == lcd_id)) {
			return lcd_kit_map[i].lcd_name;
		}
	}
	/*use defaut panel*/
	return LCD_KIT_DEFAULT_PANEL;
}

static int lcd_kit_parse_disp_info(char* compatible)
{
	/*quickly sleep out*/
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,quickly-sleep-out-support", &disp_info->quickly_sleep_out.support, 0);
	if (disp_info->quickly_sleep_out.support) {
		lcd_kit_parse_get_u32_default(compatible, "lcd-kit,quickly-sleep-out-interval", &disp_info->quickly_sleep_out.interval, 0);
	}
	/*tp color support*/
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,tp-color-support", &disp_info->tp_color.support, 0);
	if (disp_info->tp_color.support) {
		lcd_kit_parse_dcs_cmds(compatible, "lcd-kit,tp-color-cmds", &disp_info->tp_color.cmds);
	}
	/*dsi1 support*/
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,dsi1-support", &disp_info->dsi1_cmd_support, 0);
	return LCD_KIT_OK;
}

static int lcd_kit_vesa_para_parse(char* compatible, struct hisi_panel_info* pinfo)
{
	if (!compatible) {
		LCD_KIT_ERR("compatible is null\n");
		return LCD_KIT_FAIL;
	}
	if (!pinfo) {
		LCD_KIT_ERR("pinfo is null\n");
		return LCD_KIT_FAIL;
	}

	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,vesa-slice-width", &pinfo->vesa_dsc.slice_width, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,vesa-slice-height", &pinfo->vesa_dsc.slice_height, 0);
	return LCD_KIT_OK;
}

static int lcd_kit_pinfo_init(char* compatible, struct hisi_panel_info* pinfo)
{
	int ret = LCD_KIT_OK;
	uint32_t pixel_clk = 0;

	if (!compatible) {
		LCD_KIT_ERR("compatible is null\n");
		return LCD_KIT_FAIL;
	}
	if (!pinfo) {
		LCD_KIT_ERR("pinfo is null\n");
		return LCD_KIT_FAIL;
	}
	/*panel info*/
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-xres", &pinfo->xres, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-yres", &pinfo->yres, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-width", &pinfo->width, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-height", &pinfo->height, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-orientation", &pinfo->orientation, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-bpp", &pinfo->bpp, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-bgr-fmt", &pinfo->bgr_fmt, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-bl-type", &pinfo->bl_set_type, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-bl-min", &pinfo->bl_min, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-bl-max", &pinfo->bl_max, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-bl-ic-ctrl-type", &pinfo->bl_ic_ctrl_mode, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,blpwm-div", &pinfo->blpwm_div, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-cmd-type", &pinfo->type, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-ifbc-type", &pinfo->ifbc_type, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-pxl-clk", &pixel_clk, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,panel-pxl-clk-div", &pinfo->pxl_clk_rate_div, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,h-back-porch", &pinfo->ldi.h_back_porch, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,h-front-porch", &pinfo->ldi.h_front_porch, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,h-pulse-width", &pinfo->ldi.h_pulse_width, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,v-back-porch", &pinfo->ldi.v_back_porch, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,v-front-porch", &pinfo->ldi.v_front_porch, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,v-pulse-width", &pinfo->ldi.v_pulse_width, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,ldi-hsync-plr", &pinfo->ldi.hsync_plr, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,ldi-vsync-plr", &pinfo->ldi.vsync_plr, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,ldi-pixel-clk-plr", &pinfo->ldi.pixelclk_plr, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,ldi-data-en-plr", &pinfo->ldi.data_en_plr, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-lane-nums", &pinfo->mipi.lane_nums, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-color-mode", &pinfo->mipi.color_mode, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-vc", &pinfo->mipi.vc, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-dsi-bit-clk", &pinfo->mipi.dsi_bit_clk, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-max-tx-esc-clk", &pinfo->mipi.max_tx_esc_clk, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-burst-mode", &pinfo->mipi.burst_mode, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-dsi-bit-clk-val1", &pinfo->mipi.dsi_bit_clk_val1, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-dsi-bit-clk-val2", &pinfo->mipi.dsi_bit_clk_val2, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-dsi-bit-clk-val3", &pinfo->mipi.dsi_bit_clk_val3, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-dsi-bit-clk-val4", &pinfo->mipi.dsi_bit_clk_val4, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-dsi-bit-clk-val5", &pinfo->mipi.dsi_bit_clk_val5, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-non-continue-enable", &pinfo->mipi.non_continue_en, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-clk-post-adjust", &pinfo->mipi.clk_post_adjust, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-data-t-hs-trial-adjust", &pinfo->mipi.data_t_hs_trial_adjust, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-rg-vrefsel-vcm-adjust", &pinfo->mipi.rg_vrefsel_vcm_adjust, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-phy-mode", &pinfo->mipi.phy_mode, 0);
	lcd_kit_parse_get_u32_default(compatible, "lcd-kit,mipi-lp11-flag", &pinfo->mipi.lp11_flag, 0);
	pinfo->pxl_clk_rate = pixel_clk * 1000000UL;
	pinfo->lcd_type = LCD_KIT;
	pinfo->lcd_name = disp_info->lcd_name;
	pinfo->mipi.dsi_bit_clk_upt = pinfo->mipi.dsi_bit_clk;
	pinfo->mipi.max_tx_esc_clk = pinfo->mipi.max_tx_esc_clk * 1000000;
	return ret;
}

int lcd_kit_parse_dt(char* compatible)
{
	if (!compatible) {
		LCD_KIT_ERR("compatible is null");
		return LCD_KIT_FAIL;
	}
	/*parse display info*/
	lcd_kit_parse_disp_info(compatible);
	return LCD_KIT_OK;
}

int lcd_kit_utils_init(struct hisi_panel_info* pinfo)
{
	int ret = LCD_KIT_OK;

	/*pinfo init*/
	lcd_kit_pinfo_init(disp_info->compatible, pinfo);
	/*parse panel dts*/
	lcd_kit_parse_dt(disp_info->compatible);
	/*parse vesa parameters*/
	lcd_kit_vesa_para_parse(disp_info->compatible, pinfo);
	/*config compress setting*/
	lcd_kit_compress_config(pinfo->ifbc_type, pinfo);
	if (disp_info->dynamic_gamma_support) {
		ret = lcd_kit_write_gm_to_reserved_mem();
		if (ret < LCD_KIT_OK) {
			LCD_KIT_ERR("Writing the gamma data to shared memory is failed!");
		}
	}
	return ret;
}
