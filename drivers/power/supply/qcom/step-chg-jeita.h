/* Copyright (c) 2017 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __STEP_CHG_H__
#define __STEP_CHG_H__

#define MAX_STEP_CHG_ENTRIES	8

#define MAX_STEP_FV_FCC_SIZE	3
#define MAX_STEP_FV_STEP_SIZE	2
#define MAX_STEP_FCC_STEP_SIZE	1

#define is_between(left, right, value) \
		(((left) >= (right) && (left) >= (value) \
			&& (value) >= (right)) \
		|| ((left) <= (right) && (left) <= (value) \
			&& (value) <= (right)))

enum sw_dt_chg_cfg_idx {
	JEITA_FCC_CFG = 0,
	JEITA_FV_CFG,
};

int qcom_step_chg_init(bool, bool);
void qcom_step_chg_deinit(void);
void sw_dt_set_step_chg_cfg(int *cfg, int cfg_len, enum sw_dt_chg_cfg_idx  mode);
void sw_dt_set_step_chg_hysteresis(int hysteresis, enum sw_dt_chg_cfg_idx  mode);
#endif /* __STEP_CHG_H__ */
