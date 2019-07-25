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
** =============================================================================
*/

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/of.h>
#include <huawei_platform/log/hw_log.h>
#include <linux/platform_device.h>
#include <linux/i2c.h>
#include <linux/regmap.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/of_irq.h>
#include <linux/of_gpio.h>
#include <linux/of.h>
#include <linux/delay.h>

#include <linux/gpio.h>
#include <linux/input.h>
#include <linux/of_device.h>
#include <linux/i2c-dev.h>

#ifdef CONFIG_HUAWEI_DSM_AUDIO_MODULE
#define CONFIG_HUAWEI_DSM_AUDIO
#endif
#ifdef CONFIG_HUAWEI_DSM_AUDIO
#include <dsm/dsm_pub.h>
#endif

#include "adsp_misc.h"

#define HWLOG_TAG adsp_misc
#define RETRY_COUNT	3
#define SIZE_LIMIT		(512)
#define QUAT_MI2S_RX_PORT_ID 4102
#define QUAT_MI2S_TX_PORT_ID 4103

#define AFE_TFA_SET_COMMEND	0x1000B921
#define AFE_TFA_SET_BYPASS	0x1000B923
#define MIN_PARAM_IN  sizeof(adsp_misc_ctl_info_t)
#define MIN_PARAM_OUT sizeof(adsp_misc_data_pkg_t)


static struct mutex adsp_misc_mutex;

HWLOG_REGIST();

static DEFINE_SEMAPHORE(s_misc_sem);

static int adsp_misc_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	hwlog_debug("%s: Device opened!\n", __func__);
	return ret;
}
static int adsp_misc_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	hwlog_debug("%s: Device released!\n", __func__);
	return ret;
}
extern int send_tfa_cal_apr(void *buf, int cmd_size, bool bRead);

static ssize_t adsp_misc_read(struct file *file, char __user *buf,
					size_t nbytes, loff_t *pos)
{
	int ret = 0;
	uint8_t *buffer = NULL;

	hwlog_debug("%s: Read %d bytes from adsp_misc !\n", __func__, nbytes);

	if ((nbytes == 0)||(buf == NULL))
		return 0;

	mutex_lock(&adsp_misc_mutex);

	buffer = kmalloc(nbytes, GFP_KERNEL);
	if (buffer == NULL) {
		pr_err("Can not allocate memory\n");
		ret = -ENOMEM;
		goto err_out;
	}

	ret = send_tfa_cal_apr(buffer, nbytes, true);
	if (ret) {
		pr_err("dsp_msg_read error: %d\n", ret);
		ret = -EFAULT;
		goto err_out;
	}

	ret = copy_to_user(buf, buffer, nbytes);
	if (ret) {
		pr_err("copy_to_user error: %d\n", ret);
		ret = -EFAULT;
		goto err_out;
	}

	kfree(buffer);
	*pos += nbytes;
	mutex_unlock(&adsp_misc_mutex);
	return (ssize_t)nbytes;

err_out:
	if (buffer) {
		kfree(buffer);
	}
	mutex_unlock(&adsp_misc_mutex);
	return ret;
}

static ssize_t adsp_misc_write(struct file *file,
			 const char __user *buf, size_t nbytes, loff_t *ppos)
{
	uint8_t *buffer = NULL;
	int err = 0;

	hwlog_debug("%s: Write %d bytes to adsp_misc !\n", __func__, nbytes);

	if ((nbytes == 0)||(buf == NULL))
		return 0;	/* msg_file.name is not used */

	mutex_lock(&adsp_misc_mutex);

	buffer = kmalloc(nbytes, GFP_KERNEL);
	if ( buffer == NULL ) {
		pr_err("Can not allocate memory\n");
		err = -ENOMEM;
		goto err_out;
	}

	if (copy_from_user(buffer, buf, nbytes)) {
		pr_err("Copy from user space err!\n");
		err = -EFAULT;
		goto err_out;
	}


	err = send_tfa_cal_apr(buffer, nbytes, false);
	if (err) {
		pr_err("dsp_msg error: %d\n", err);
		goto err_out;
	}

	kfree(buffer);
	mdelay(2);
	mutex_unlock(&adsp_misc_mutex);
	return (ssize_t)nbytes;
err_out:
	if(buffer) {
		kfree(buffer);
	}
	mutex_unlock(&adsp_misc_mutex);
	return err;
}

static int tfa98xx_adsp_cmd(int cmd_id, uint8_t *buf, ssize_t buf_sz)
{
	int ret = 0;

	if (buf == NULL) {
		return -EINVAL;
	}
	memset(buf, 0x00, buf_sz);

	buf[0] = (cmd_id >> 16) & 0xff;
	buf[1] = (cmd_id >> 8) & 0xff;
	buf[2] = cmd_id & 0xff;

	ret = send_tfa_cal_apr(buf, buf_sz, false);
	mdelay(2);
	if (!ret && ((cmd_id & 0xff)>= 0x80)) {
		ret = send_tfa_cal_apr(buf, buf_sz, true);
	}

	return ret;
}

static int soc_adsp_get_current_R0(unsigned char *data, unsigned int len)
{
	int ret = 0;
	uint8_t *buffer = NULL;
	int count = 512;
	int cur_R0[2];

	if ((len < 4) || (NULL == data))
		return -EINVAL;

	buffer = kzalloc(count, GFP_KERNEL);
	if (buffer == NULL) {
		hwlog_err("can not allocate memory!\n");
		return -ENOMEM;
	}
	ret = tfa98xx_adsp_cmd(0x00808b, buffer, count);

	if(ret) {
		hwlog_err("Get R0 error!\n");
		goto exit;
	}
	cur_R0[0] = (buffer[5*3 + 0] <<16) + (buffer[5*3 + 1] << 8) + buffer[5*3 + 2];
	cur_R0[1] = (buffer[6*3 + 0] <<16) + (buffer[6*3 + 1] << 8) + buffer[6*3 + 2];
	hwlog_info("%s:Get current R0L = %d R0R = %d.\n", __func__, cur_R0[0], cur_R0[1]);

	if (len <= 8 && len >= 4)
		memcpy(data, cur_R0, len);

exit:
	kfree(buffer);
	return ret;
}

static int soc_adsp_get_current_Temp(unsigned char *data, unsigned int len)
{
	int ret = 0;
	uint8_t *buffer = NULL;
	int count = 512;
	int cur_Temp[2];
	if ((len < 4) || (NULL == data))
		return -EINVAL;

	buffer = kzalloc(count, GFP_KERNEL);
	if (buffer == NULL) {
		hwlog_err("can not allocate memory!\n");
		return -ENOMEM;
	}
	ret = tfa98xx_adsp_cmd(0x00808b, buffer, count);

	if(ret) {
		hwlog_err("Get Temp error!\n");
		goto exit;
	}

	cur_Temp[0] = (buffer[9*3 + 0] <<16) + (buffer[9*3 + 1] << 8) + buffer[9*3 + 2];
	cur_Temp[1] = (buffer[10*3 + 0] <<16) + (buffer[10*3 + 1] << 8) + buffer[10*3 + 2];
	hwlog_info("%s:Get current TempL = %d,TempR = %d.\n", __func__, cur_Temp[0], cur_Temp[1]);

	if (len <= 8 && len >= 4)
		memcpy(data, cur_Temp, len);

exit:
	kfree(buffer);
	return ret;
}

static int soc_adsp_get_current_F0(unsigned char *data, unsigned int len)
{
	int ret = 0;
	uint8_t *buffer = NULL;
	int count = 512;
	int cur_F0[2];

	if ((len < 4) || (NULL == data))
		return -EINVAL;

	buffer = kzalloc(count, GFP_KERNEL);
	if (buffer == NULL) {
		hwlog_err("can not allocate memory!\n");
		return -ENOMEM;
	}
	ret = tfa98xx_adsp_cmd(0x00808b, buffer, count);

	if(ret) {
		hwlog_err("Get F0 error!\n");
		goto exit;
	}

	cur_F0[0] = (buffer[41*3 + 0] <<16) + (buffer[41*3 + 1] << 8) + buffer[41*3 + 2];
	cur_F0[1] = (buffer[42*3 + 0] <<16) + (buffer[42*3 + 1] << 8) + buffer[42*3 + 2];
	hwlog_info("%s:Get current F0_L = %d, F0_R = %d!\n", __func__, cur_F0[0], cur_F0[1]);
	if (len <= 8 && len >= 4)
		memcpy(data, cur_F0, len);

exit:
	kfree(buffer);
	return ret;
}

extern int send_tfa_cal_in_band(void *buf, int cmd_size, int param_id);

static int soc_adsp_set_tfa_cal(void *cal_buf, int size) {
	if(cal_buf == NULL){
		hwlog_err("%s:invalid input data buf!\n", __func__);
		return -EINVAL;
	}
	int ret = 0, nr = 0;
	unsigned char bytes[3*3] = {0};

	unsigned int dsp_cal_value_left, dsp_cal_value_right;
	unsigned int *cal_value = NULL;

	if (size%4 != 0) {
		hwlog_err("%s:invalid input data size!\n", __func__);
		return -EINVAL;
	}

	if(size == 8) {
		cal_value = (unsigned int *)cal_buf;
		dsp_cal_value_left = *cal_value;
		dsp_cal_value_right = *(cal_value++);

		hwlog_info("%s:send data to adsp ,cal_value_L = %d,cal_value_R = %d!\n",
			           __func__, dsp_cal_value_left, dsp_cal_value_right);

		bytes[nr++] = 0x04;
		bytes[nr++] = 0x81;
		bytes[nr++] = 0x05;

		bytes[nr++] = (uint8_t)((dsp_cal_value_left >> 16) & 0xff);
		bytes[nr++] = (uint8_t)((dsp_cal_value_left >> 8) & 0xff);
		bytes[nr++] = (uint8_t)(dsp_cal_value_left & 0xff);

		bytes[nr++] = (uint8_t)((dsp_cal_value_right >> 16) & 0xff);
		bytes[nr++] = (uint8_t)((dsp_cal_value_right >> 8) & 0xff);
		bytes[nr++] = (uint8_t)(dsp_cal_value_right & 0xff);

		ret = send_tfa_cal_in_band(bytes, sizeof(bytes), AFE_TFA_SET_COMMEND);
	}
	cal_value = NULL;

	return ret;

}

static int soc_adsp_set_tfa_disable(void)
{
	int enable = true;

	return send_tfa_cal_in_band(&enable, sizeof(enable), AFE_TFA_SET_BYPASS);
}

static int soc_adsp_set_tfa_enable(void)
{
	int enable = false;

	return send_tfa_cal_in_band(&enable, sizeof(enable), AFE_TFA_SET_BYPASS);
}


static int soc_adsp_send_param(adsp_misc_ctl_info_t *param, unsigned char *data, unsigned int len)
{
	if(param == NULL) {
		hwlog_err("%s,invalid input param!\n", __func__);
		return -EINVAL;
	}

	int ret = 0;

	int cmd = param->cmd;

#ifndef CONFIG_FINAL_RELEASE
	hwlog_info("%s: enter, cmd = %d!\n", __func__, cmd);
#endif

	switch (cmd) {
		case SET_CALIBRATION_VALUE :
			//ret = soc_adsp_set_tfa_cal(param->data, param->size);
			break;
		case CALIBRATE_MODE_START :
		case CALIBRATE_MODE_STOP :
			break;
		case GET_CURRENT_R0 :
			ret = soc_adsp_get_current_R0(data, len);
			break;
		case GET_CURRENT_TEMPRATURE :
			ret = soc_adsp_get_current_Temp(data, len);
			break;
		case GET_CURRENT_F0 :
			ret = soc_adsp_get_current_F0(data, len);
			break;
		case GET_CURRENT_Q :
			break;
		case SMARTPA_ALGO_ENABLE :
			//ret = soc_adsp_set_tfa_enable();
			break;
		case SMARTPA_ALGO_DISABLE :
			//ret = soc_adsp_set_tfa_disable();
			break;
		default :
			break;
	}

	if (ret) {
		hwlog_info("%s: send cmd = %d, ret = %d.\n", __func__, cmd, ret);
	}

	return ret;
}

static int soc_adsp_handle_sync_param(void __user *arg, int compat_mode)
{
	int ret = 0;
	adsp_misc_ctl_info_t *param_in = NULL;
	void __user *param_out = NULL;
	unsigned int param_out_len = 0;
	adsp_misc_data_pkg_t *result = NULL;

	if (!(void __user *)arg) {
		hwlog_err("%s: Invalid input arg, exit!\n", __func__);
		goto ERR;
	}

#ifdef CONFIG_COMPAT
	if(0 == compat_mode) {
#endif //CONFIG_COMPAT

		misc_io_sync_param_t par;
		memset(&par, 0, sizeof(misc_io_sync_param_t));

#ifndef CONFIG_FINAL_RELEASE
		hwlog_info("%s: copy_from_user b64 %p...\n", __func__, arg);
#endif

		if(copy_from_user(&par, arg, sizeof(misc_io_sync_param_t))) {
			hwlog_err("%s: get param head copy_from_user fail!!!\n", __func__);
			ret = -EFAULT;
			goto ERR;
		}
		param_out_len = par.out_len;
		param_out = (void __user *)par.out_param;

		hwlog_debug("%s: param in len is %d, in_param is %p", __func__, par.in_len, par.in_param);
		if ((par.in_len < MIN_PARAM_IN)||(par.in_param == NULL)) {
			hwlog_err("%s,param_in from user64 is error!\n", __func__);
			goto ERR;
		}

		param_in = kzalloc(par.in_len, GFP_KERNEL);
		if (param_in == NULL) {
			hwlog_err("%s, kzalloc param space error!\n", __func__);
			ret = -ENOMEM;
			goto ERR;
		}

		if (copy_from_user(param_in, (void __user *)par.in_param, par.in_len)) {
			hwlog_err("%s: get param date copy_from_user fail!!!\n", __func__);
			ret = -EFAULT;
			goto ERR;
		}

#ifdef CONFIG_COMPAT
	} else { // 1 == compat_mode
		misc_io_sync_param_compat_t par_compat;
		memset(&par_compat, 0, sizeof(misc_io_sync_param_compat_t));

#ifndef CONFIG_FINAL_RELEASE
		hwlog_info("%s: copy_from_user b32 %p...\n", __func__, arg);
#endif

		if (copy_from_user(&par_compat, arg, sizeof(misc_io_sync_param_compat_t))) {
			hwlog_err("%s: get set_param_compat copy_from_user fail!!!\n", __func__);
			ret = -EFAULT;
			goto ERR;
		}

		param_out_len = par_compat.out_len;
		param_out = compat_ptr(par_compat.out_param);

		hwlog_debug("%s: param in len is %d, in_param is 0x%x", __func__, par_compat.in_len, par_compat.in_param);
		if ((par_compat.in_len < MIN_PARAM_IN)||(par_compat.in_param == 0)){
			hwlog_err("%s,param_in from user32 is error!\n", __func__);
			goto ERR;
		}

		param_in = kzalloc(par_compat.in_len, GFP_KERNEL);

		if (param_in == NULL) {
			hwlog_err("%s, kzalloc get_data space error!\n", __func__);
			ret = -ENOMEM;
			goto ERR;
		}

		if(copy_from_user(param_in, compat_ptr(par_compat.in_param) ,par_compat.in_len)) {
			hwlog_err("%s: get param date copy_from_user fail!!!\n", __func__);
			ret = -EFAULT;
			goto ERR;
		}
	}
#endif //CONFIG_COMPAT

	if ((param_out_len > MIN_PARAM_OUT) && (param_out != NULL)) { //Need copy result to user space
		result = kzalloc(param_out_len, GFP_KERNEL);
		if(result == NULL) {
			hwlog_err("%s: kzalloc result memory err!!!\n", __func__);
			ret = -ENOMEM;
			goto ERR;
		}
		result->size = param_out_len - sizeof(adsp_misc_data_pkg_t);
		ret = soc_adsp_send_param(param_in, result->data, result->size);
		if (!ret) {
			if (copy_to_user(param_out, result, param_out_len)){
				hwlog_err("%s:set result copy_to_user fail!!!\n", __func__);
				ret = -EFAULT;
				goto ERR;
			}
		}
	} else {
		ret = soc_adsp_send_param(param_in, NULL, 0);
	}

ERR:
	if (param_in)
		kfree(param_in);
	if (result)
		kfree(result);

	return ret;
}

static int adsp_misc_do_ioctl(struct file *file, unsigned int command, void __user *arg, int compat_mode)
{
	int ret = -1;

	hwlog_debug("%s: enter, cmd:0x%x compat_mode=%d...\n", __func__, command, compat_mode);

	if (NULL == file) {
		hwlog_err("%s: invalid argument!!!\n", __func__);
		goto out;
	}

	switch(command) {
		case ADSP_MISC_IOCTL_ASYNCMSG :
			break;
		case ADSP_MISC_IOCTL_SYNCMSG :
			mutex_lock(&adsp_misc_mutex);
			ret = soc_adsp_handle_sync_param(arg, compat_mode);
			mutex_unlock(&adsp_misc_mutex);
			break;
		default :
			ret = -EFAULT;
	}

out:
	return ret;
}

static long adsp_misc_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	return adsp_misc_do_ioctl(file, command, (void __user * )arg, 0);
}


#ifdef CONFIG_COMPAT
static long adsp_misc_ioctl_compat(struct file *file, unsigned int command, unsigned long arg)
{
	switch(command) {
		case ADSP_MISC_IOCTL_ASYNCMSG_COMPAT :
			command = ADSP_MISC_IOCTL_ASYNCMSG;
			break;
		case ADSP_MISC_IOCTL_SYNCMSG_COMPAT :
			command = ADSP_MISC_IOCTL_SYNCMSG;
			break;
		default :
			break;
	}
	return adsp_misc_do_ioctl(file, command,  compat_ptr((unsigned int)arg), 1);
}
#else
#define adsp_misc_ioctl_compat NULL
#endif  //CONFIG_COMPAT

static const struct file_operations adsp_misc_fops = {
	.owner          = THIS_MODULE,
	.open           = adsp_misc_open,
	.release        = adsp_misc_release,
#ifndef CONFIG_FINAL_RELEASE
	.read           = adsp_misc_read,  //24bits BIG ENDING DATA
	.write          = adsp_misc_write, //24bits BIG ENDING DATA
#endif
	.unlocked_ioctl = adsp_misc_ioctl, //32bits LITTLE ENDING DATA
#ifdef CONFIG_COMPAT
	.compat_ioctl   = adsp_misc_ioctl_compat,  //32bits LITTLE ENDING DATA
#endif
};

static struct miscdevice adsp_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "adsp_misc",
	.fops  = &adsp_misc_fops,
};
static int __init adsp_misc_init(void)
{
	int ret = 0;

	ret = misc_register(&adsp_misc_dev);
	if (0 != ret) {
		hwlog_err("%s: register miscdev failed(%d)!!!\n", __func__, ret);
		goto err_out;
	}

	mutex_init(&adsp_misc_mutex);

	return 0;

err_out:
	return ret;
}

static void __exit adsp_misc_exit(void)
{
	misc_deregister(&adsp_misc_dev);
	return;
}

module_init(adsp_misc_init);
module_exit(adsp_misc_exit);

/*lint -e753*/
MODULE_DESCRIPTION("adsp_misc driver");
MODULE_LICENSE("GPL");

