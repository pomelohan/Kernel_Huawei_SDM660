/*
** =============================================================================
** Copyright (c) 2017 Huawei Device Co.Ltd
**
** This program is free software; you can redistribute it and/or modify it under
** the terms of the GNU General Public License as published by the Free Software
** Foundation; version 2.
**
** This program is distributed in the hope that it will be useful, but WITHOUT
** ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
** FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License along with
** this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
** Street, Fifth Floor, Boston, MA 02110-1301, USA.
**
**Author: 
** =============================================================================
*/

#ifndef __SMARTPAKIT_DEFS_H__
#define __SMARTPAKIT_DEFS_H__

#define SMARTPAKIT_NAME_MAX    (64)
#define MAX_PA_NUMBER          (4)

// different device(rec or spk) use different algo params
typedef enum smartpakit_out_device {
	SMARTPAKIT_OUT_DEVICE_SPEAKER = 0,
	SMARTPAKIT_OUT_DEVICE_RECEIVER,

	SMARTPAKIT_OUT_DEVICE_MAX,
} smartpakit_out_device_t;

// Now, up to only support two pa
typedef enum smartpakit_pa_id {
	SMARTPAKIT_PA_ID_BEGIN = 0,
	SMARTPAKIT_PA_ID_PRIL  = SMARTPAKIT_PA_ID_BEGIN,
	SMARTPAKIT_PA_ID_PRIR,
	SMARTPAKIT_PA_ID_SECL,
	SMARTPAKIT_PA_ID_SECR,

	SMARTPAKIT_PA_ID_MAX,
	SMARTPAKIT_PA_ID_ALL = 0xFF,
} smartpakit_pa_id_t;

enum smartPA_cmd {
	GET_CURRENT_R0 = 0,
	GET_CURRENT_TEMPRATURE,      /*--1-*/
	GET_CURRENT_F0,              /*--2-*/
	GET_CURRENT_Q,               /*--3-*/
	GET_PARAMETERS,              /*--4-*/
	GET_CURRENT_POWER,           /*--5-*/
	GET_CMD_NUM,                 /*--6-*/

	SET_ALGO_SECENE,             /*--7-*/
	SET_CALIBRATION_VALUE,       /*--8-*/
	CALIBRATE_MODE_START,        /*--9-*/
	CALIBRATE_MODE_STOP,         /*-10-*/
	SET_F0_VALUE,                /*-11-*/

	SET_PARAMETERS,              /*-12-*/
	SET_VOICE_VOLUME,            /*-13-*/
	SET_LOW_POWER_MODE,          /*-14-*/
	SET_SAFETY_STRATEGY,         /*-15-*/
	SET_FADE_CONFIG,             /*-16-*/
	SET_SCREEN_ANGLE,            /*-17-*/
	SMARTPA_ALGO_ENABLE,         /*-18-*/
	SMARTPA_ALGO_DISABLE,        /*-19-*/
	CMD_NUM,
	// new
	SMARTPA_PRINT_MCPS,
	SMARTPA_DEBUG,
	SMARTPA_DSP_ENABLE,
	SMARTPA_DSP_DISABLE,
};

struct tfa98xx_calibratedata
{
	int Tcof;
	int Fres;
	int Qfactory;
	int ReT;
	int Temp;
};

// which chip provider
typedef enum smartpakit_chip_vendor {
	SMARTPAKIT_CHIP_VENDOR_MAXIM = 0, // max98925
	SMARTPAKIT_CHIP_VENDOR_NXP,       // tfa9872, tfa9895
	SMARTPAKIT_CHIP_VENDOR_TI,        // tas2560
	SMARTPAKIT_CHIP_VENDOR_OTHER,     // other vendor

	SMARTPAKIT_CHIP_VENDOR_MAX,
} smartpakit_chip_vendor_t;

typedef struct smartpakit_info {
	// common info
	unsigned int  soc_platform;
	unsigned int  algo_in;
	unsigned int  out_device;
	unsigned int  pa_num;

	// smartpa chip info
	unsigned int  algo_delay_time;
	unsigned int  chip_vendor;
	char chip_model[SMARTPAKIT_NAME_MAX];
} smartpakit_info_t;
typedef struct misc_io_async_param {
	unsigned int para_length;
	unsigned char*   param;
}misc_io_async_param_t;

typedef struct misc_io_sync_param {
	unsigned int in_len;
	unsigned char *in_param;
	unsigned int out_len;
	unsigned char *out_param;
}misc_io_sync_param_t;


typedef struct adsp_misc_ctl_info {
	smartpakit_info_t pa_info;
	unsigned int    uwSize;           /*param size*/
	unsigned short  cmd;
	unsigned short  size;
	unsigned char  data[0];
}adsp_misc_ctl_info_t;

typedef struct misc_io_async_param_compat {
	unsigned int para_length;
	unsigned int param;
}misc_io_async_param_compat_t;

typedef struct misc_io_sync_param_compat {
	unsigned int in_len;
	unsigned int in_param;
	unsigned int out_len;
	unsigned int out_param;
}misc_io_sync_param_compat_t;

typedef struct adsp_misc_data_pkg {
	unsigned short  cmd;
	unsigned short  size;
	unsigned char  data[0];
}adsp_misc_data_pkg_t;

//The following is ioctrol command sent from AP to ADSP Misc device, DASP Misc side need response these commands.
#define ADSP_MISC_IOCTL_ASYNCMSG		 _IOWR('A', 0x0, struct misc_io_async_param)		  //AP send async mesg to ADSP
#define ADSP_MISC_IOCTL_SYNCMSG 		 _IOW('A', 0x1, struct misc_io_sync_param)			  //AP send sync mesg to ADSP

#define ADSP_MISC_IOCTL_ASYNCMSG_COMPAT		    _IOWR('A', 0x0, struct misc_io_async_param_compat)	//AP send async mesg to ADSP
#define ADSP_MISC_IOCTL_SYNCMSG_COMPAT		    _IOW('A', 0x1, struct misc_io_sync_param_compat)	//AP send sync mesg to ADSP

#endif // __SMARTPAKIT_DEFS_H__

