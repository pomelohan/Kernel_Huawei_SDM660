/*
 * Copyright (C) 2012-2015 HUAWEI, Inc.
 * Author: HUAWEI, Inc.
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/notifier.h>
#include <linux/wakelock.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <dsm/dsm_pub.h>
#include <linux/delay.h>
#include <dsm/dsm_pub.h>
#include <linux/qpnp/qpnp-adc.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/thermal.h>
#include <linux/regulator/consumer.h>
#include <linux/huawei_adc.h>

extern int usb_charger_register_notifier(struct notifier_block *nb);
extern int usb_charger_notifier_unregister(struct notifier_block *nb);

struct uscp_device_info
{
    struct device   *dev;
    struct device_node *np_node;
    struct workqueue_struct *uscp_wq;
    struct work_struct uscp_check_wk;
    struct power_supply     *usb_psy;
    struct power_supply     *batt_psy;
    struct power_supply     *bms_psy;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
	struct power_supply		uscp_psy;
#else
	struct power_supply		*uscp_psy;
#endif
    struct hrtimer timer;
    int usb_present;
    int gpio_uscp;
    int uscp_threshold_tusb;
    int open_mosfet_temp;
    int open_hiz_temp;
    int close_mosfet_temp;
    int interval_switch_temp;
    int check_interval;
    int keep_check_cnt;
    int no_need_uscp;//support uscp or not
	bool switch_mode;
	bool dmd_hiz_enable;
	struct delayed_work type_work;
	struct notifier_block nb;

};

static struct dsm_dev dsm_uscp =
{
    .name = "dsm_usb_short_circuit_protect",
    .fops = NULL,
    .buff_size = 1024, /* buffer size in bytes */
};
#define		TRUE					1
#define		FALSE					0
#define		INVALID_DELTA_TEMP		0
#define		USCP_DEFAULT_CHK_CNT	(-1)
#define		USCP_START_CHK_CNT		0
#define		USCP_END_CHK_CNT		1001
#define		USCP_CHK_CNT_STEP		1
#define		USCP_INSERT_CHG_CNT		1100
#define		FAST_MONITOR_INTERVAL	300  /*300 ms*/
#define		NORMAL_MONITOR_INTERVAL	10000  /*10000 ms*/
#define		GPIO_HIGH				1
#define		GPIO_LOW				0
#define		INTERVAL_0				0
#define		RETRY_CNT				3
#define		USB_TEMP_CNT			2
#define		TUSB_TEMP_UPPER_LIMIT	100
#define		TUSB_TEMP_LOWER_LIMIT	(-30)
#define		COVERSE_TEMP_UNIT		10
#define		INVALID_BATT_TEMP		(-255)
#define 	ADC_VOL_INIT			(-1)
#define		AVG_COUNT					3
#define		FG_NOT_READY					0
#define     DEFAULT_TUSB_THRESHOLD       40
#define 	HIZ_ENABLE 1
#define 	HIZ_DISABLE 0
#define 	HIZ_MODE 1
#define 	NOT_HIZ_MODE 0
#define 	DMD_NOTIFY_HIZ_ENABLE 1
#define 	DMD_NOTIFY_HIZ_DISABLE 0
#define 	DMD_HIZ_DISABLE 0
#define     SLEEP_10MS   (10)

static int protect_enable = FALSE;
static int protect_dmd_notify_enable = TRUE;
static int is_uscp_mode = 0;
static int is_hiz_mode = NOT_HIZ_MODE;
 static int protect_dmd_notify_enable_hiz = DMD_NOTIFY_HIZ_ENABLE;

/* temp/voltage mapping */
static int T_A_TABLE[][2] =
{
    {-40, 1833},
    {-39, 1830},
    {-38, 1827},
    {-37, 1824},
    {-36, 1820},
    {-35, 1816},
    {-34, 1812},
    {-33, 1808},
    {-32, 1803},
    {-31, 1798},
    {-30, 1793},
    {-29, 1788},
    {-28, 1782},
    {-27, 1776},
    {-26, 1770},
    {-25, 1764},
    {-24, 1757},
    {-23, 1749},
    {-22, 1742},
    {-21, 1734},
    {-20, 1725},
    {-19, 1716},
    {-18, 1707},
    {-17, 1697},
    {-16, 1687},
    {-15, 1677},
    {-14, 1666},
    {-13, 1655},
    {-12, 1643},
    {-11, 1631},
    {-10, 1618},
    {-9,  1605},
    {-8,  1591},
    {-7,  1577},
    {-6,  1562},
    {-5,  1547},
    {-4,  1531},
    {-3,  1515},
    {-2,  1499},
    {-1,  1482},
    {0,   1465},
    {1,   1447},
    {2,   1429},
    {3,   1410},
    {4,   1391},
    {5,   1372},
    {6,   1352},
    {7,   1332},
    {8,   1311},
    {9,   1291},
    {10,  1270},
    {11,  1248},
    {12,  1227},
    {13,  1205},
    {14,  1183},
    {15,  1161},
    {16,  1139},
    {17,  1117},
    {18,  1094},
    {19,  1072},
    {20,  1049},
    {21,  1027},
    {22,  1004},
    {23,  982 },
    {24,  960 },
    {25,  938 },
    {26,  915 },
    {27,  893 },
    {28,  872 },
    {29,  850 },
    {30,  829 },
    {31,  808 },
    {32,  787 },
    {33,  766 },
    {34,  746 },
    {35,  726 },
    {36,  706 },
    {37,  687 },
    {38,  668 },
    {39,  649 },
    {40,  631 },
    {41,  613 },
    {42,  595 },
    {43,  578 },
    {44,  561 },
    {45,  544 },
    {46,  528 },
    {47,  512 },
    {48,  497 },
    {49,  482 },
    {50,  467 },
    {51,  453 },
    {52,  439 },
    {53,  426 },
    {54,  412 },
    {55,  400 },
    {56,  387 },
    {57,  375 },
    {58,  363 },
    {59,  352 },
    {60,  341 },
    {61,  330 },
    {62,  320 },
    {63,  310 },
    {64,  300 },
    {65,  290 },
    {66,  281 },
    {67,  272 },
    {68,  264 },
    {69,  255 },
    {70,  247 },
    {71,  239 },
    {72,  232 },
    {73,  224 },
    {74,  217 },
    {75,  210 },
    {76,  204 },
    {77,  197 },
    {78,  191 },
    {79,  185 },
    {80,  179 },
    {81,  174 },
    {82,  168 },
    {83,  163 },
    {84,  158 },
    {85,  153 },
    {86,  148 },
    {87,  143 },
    {88,  139 },
    {89,  135 },
    {90,  131 },
    {91,  126 },
    {92,  123 },
    {93,  119 },
    {94,  115 },
    {95,  112 },
    {96,  108 },
    {97,  105 },
    {98,  102 },
    {99,  99  },
    {100, 96  },
    {101, 93  },
    {102, 90  },
    {103, 87  },
    {104, 85  },
    {105, 82  },
    {106, 80  },
    {107, 78  },
    {108, 75  },
    {109, 73  },
    {110, 71  },
    {111, 69  },
    {112, 67  },
    {113, 65  },
    {114, 63  },
    {115, 61  },
    {116, 60  },
    {117, 58  },
    {118, 56  },
    {119, 55  },
    {120, 53  },
    {121, 52  },
    {122, 50  },
    {123, 49  },
    {124, 47  },
    {125, 46  },

};

static struct dsm_client *uscp_client = NULL;
static struct uscp_device_info* g_di = NULL;
static struct wake_lock uscp_wakelock;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
static char *uscp_power_supplied_from[] = {
	"usb",
};
#endif

static int get_propety_int(struct power_supply *psy, int propery)
{
	int rc = 0;
	union power_supply_propval ret = {0, };

	if (!psy) {
		pr_err("get input source power supply node failed!\n");
		return -EINVAL;
	}
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
	rc = psy->get_property(psy, propery, &ret);
#else
	rc = psy->desc->get_property(psy, propery, &ret);
#endif
	if (rc) {
		pr_err("Couldn't get type rc = %d\n", rc);
		ret.intval = -EINVAL;
	}

	return ret.intval;
}
static int set_propety_int(struct power_supply *psy,
                enum power_supply_property prop,
                const union power_supply_propval *val)
{
	int rc = 0;

	if (!psy|| !val||!(psy->desc)) {
		pr_err("get input source power supply node failed!\n");
		return -EINVAL;
	}
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
	rc = psy->set_property(psy, prop, val);
#else
	rc = psy->desc->set_property(psy, prop, val);
#endif
	if (rc < 0) {
		pr_err("Couldn't set type rc = %d\n", rc);
	}

	return rc;
}
void charge_set_hiz_enable(int hiz_mode)
{
   int rc = 0;
   union power_supply_propval val ={0};
   val.intval  = hiz_mode;



   rc =set_propety_int(g_di->batt_psy,POWER_SUPPLY_PROP_HIZ_MODE,&val);
   if (rc <0)
     pr_err("Couldn't set hiz enable\n");

}
static bool is_factory_mode = false;
static int __init early_parse_factory_mode(char *cmdline)
{
    if (!cmdline) {
        pr_err("%s: invalid param, fatal error\n", __func__);
        return 0;
    }
    if ((cmdline) && !strncmp(cmdline, "factory", strlen("factory"))) {
        is_factory_mode = true;
    }

    return 0;
}
early_param("androidboot.huawei_swtype", early_parse_factory_mode);
static void uscp_wake_lock(void)
{
    if(!wake_lock_active(&uscp_wakelock))
    {
        pr_info("wake lock\n");
        wake_lock(&uscp_wakelock);
    }
}

static void uscp_wake_unlock(void)
{
    if(wake_lock_active(&uscp_wakelock))
    {
        pr_info("wake unlock\n");
        wake_unlock(&uscp_wakelock);
    }
}

static void charge_type_handler(struct uscp_device_info* di, int type)
{
    int interval = 0;

    if ((!protect_enable)||(NULL == di))
        return;
    //if ((POWER_SUPPLY_TYPE_USB_DCP == type)||(POWER_SUPPLY_TYPE_USB == type) || (POWER_SUPPLY_TYPE_USB_CDP == type)||(POWER_SUPPLY_TYPE_USB_HVDCP == type))
    if (TRUE == type)
    {
        if (hrtimer_active(&(di->timer)))
        {
            pr_info("timer already armed , do nothing\n");
        }
        else
        {
            pr_info("start uscp check\n");
            interval = INTERVAL_0;
            /*record 30 seconds after the charger just insert; 30s = (1100 - 1001 + 1)*300ms */
            di->keep_check_cnt = USCP_INSERT_CHG_CNT;
            hrtimer_start(&di->timer, ktime_set(interval/MSEC_PER_SEC, (interval % MSEC_PER_SEC) * USEC_PER_SEC), HRTIMER_MODE_REL);
        }
    }
    else
    {
        pr_info("charger type = %d, do nothing\n", type);
    }
}


static int get_one_adc_sample(void)
{
    int i =0;
    const int retry_times = RETRY_CNT;
    int T_sample = ADC_VOL_INIT;
    if(NULL == g_di)
    {
         pr_err("adc read fail!\n");
         return T_sample;
    }
    for (i = 0; i < retry_times; ++i)
    {
        T_sample = get_adc_converse_voltage(g_di->np_node,g_di->switch_mode);

        if (T_sample < 0)
        {
            pr_err("adc read fail!\n");
        }
        else
        {
             break;
        }
    }
    return T_sample;
}

/* get temp by searching the voltage-temp table */
static int adc_to_temp(int adc_value)
{
    int table_size = sizeof(T_A_TABLE)/sizeof(T_A_TABLE[0]);
    int high = table_size - 1;
    int low = 0;
    int mid = 0;

    if (adc_value >= T_A_TABLE[0][1])
        return T_A_TABLE[0][0];
    if (adc_value <= T_A_TABLE[table_size - 1][1])
        return T_A_TABLE[table_size - 1][0];
    /*use binary search*/
    while (low < high)
    {
        pr_debug("low = %d,high = %d!\n", low, high);
        mid = (low + high) / 2;
        if (0 == mid)
            return T_A_TABLE[1][0];
        if (adc_value > T_A_TABLE[mid][1])
        {
            if (adc_value < T_A_TABLE[mid - 1][1])
                return T_A_TABLE[mid][0];
            high = mid - 1;
        }
        else if(adc_value < T_A_TABLE[mid][1])
        {
            if (adc_value >= T_A_TABLE[mid + 1][1])
                return T_A_TABLE[mid + 1][0];
            low = mid + 1;
        }
        else
            return T_A_TABLE[mid][0];
    }
    pr_err("transform error!\n");
    return 0;
}

static int get_usb_temp_value(void)
{
    int i = 0;
    int cnt = 0;
    int adc_temp = 0;
    const int sample_num = AVG_COUNT; // use 3 samples to get an average value
    int sum = 0;
    int temp = 0;

    for (i = 0; i < sample_num; ++i)
    {
        adc_temp = get_one_adc_sample();
        if (adc_temp >= 0)
        {
            sum += adc_temp;
            ++cnt;
        }
        else
        {
            pr_err(" get temperature fail!\n");
        }
    }
    if (cnt > 0)
    {
        temp = adc_to_temp(sum/cnt);
        return temp;
    }
    else
    {
        pr_err("use 0 as default temperature!\n");
        return 0;
    }
}
static int get_batt_temp_value(void)
{
    int rc = 0;
    int ret = 0;

    if((g_di == NULL)||(g_di->batt_psy == NULL))
    {
        pr_err(" %s g_di is NULL!\n",__func__);
        return INVALID_BATT_TEMP;
    }

    rc = get_propety_int(g_di->batt_psy, POWER_SUPPLY_PROP_PROFILE_STATUS);
    if((rc == -EINVAL)||(rc == FG_NOT_READY))
    {
        pr_err(" %s  get profile error!\n",__func__);
        return INVALID_BATT_TEMP;
    }

	ret = get_propety_int(g_di->batt_psy, POWER_SUPPLY_PROP_TEMP);
    if(ret == -EINVAL)
    {
        pr_err(" %s  get temp error!\n",__func__);
        return INVALID_BATT_TEMP;
    }

    return ret/COVERSE_TEMP_UNIT;

}

static void set_interval(struct uscp_device_info* di, int temp)
{
    if(NULL == di)
    {
        pr_err(" %s di is NULL!\n",__func__);
        return;
    }

    if (temp > di->interval_switch_temp) {
        di->check_interval = FAST_MONITOR_INTERVAL;
        di->keep_check_cnt = USCP_START_CHK_CNT;
        pr_info("cnt = %d!\n", di->keep_check_cnt);
    } else {
        if (di->keep_check_cnt > USCP_END_CHK_CNT) {
            /*check the temperature per 0.3 second for 100 times ,when the charger just insert.*/
            pr_info("cnt = %d!\n", di->keep_check_cnt);
            di->keep_check_cnt -= USCP_CHK_CNT_STEP;
            di->check_interval = FAST_MONITOR_INTERVAL;
            is_uscp_mode = FALSE;
        } else if (di->keep_check_cnt == USCP_END_CHK_CNT) {
            /* reset the flag when the temperature status is stable*/
            pr_info("cnt = %d!\n", di->keep_check_cnt);
            di->keep_check_cnt = USCP_DEFAULT_CHK_CNT;
            di->check_interval = NORMAL_MONITOR_INTERVAL;
            is_uscp_mode = FALSE;
            uscp_wake_unlock();
        } else if (di->keep_check_cnt >= USCP_START_CHK_CNT) {
            pr_info("cnt = %d!\n", di->keep_check_cnt);
            di->keep_check_cnt = di->keep_check_cnt + USCP_CHK_CNT_STEP;
            di->check_interval = FAST_MONITOR_INTERVAL;
        } else {
            di->check_interval = NORMAL_MONITOR_INTERVAL;
            is_uscp_mode = FALSE;
        }
    }
}
static void protection_process(struct uscp_device_info* di, int tbatt, int tusb)
{
    int gpio_value = 0;
    int tdiff = 0;

    if(NULL == di)
    {
        pr_err(" %s di is NULL!\n",__func__);
        return;
    }
    tdiff = tusb - tbatt;

    gpio_value = gpio_get_value(di->gpio_uscp);
	if ((INVALID_BATT_TEMP != tbatt) &&(tusb >= di->uscp_threshold_tusb) && (tdiff >= di->open_hiz_temp)){
        is_hiz_mode = HIZ_MODE;
        pr_err("enable charge hiz!\n");
        charge_set_hiz_enable(HIZ_ENABLE);
    }
    if ((INVALID_BATT_TEMP != tbatt) &&(tusb >= di->uscp_threshold_tusb) && (tdiff >= di->open_mosfet_temp)) {
        uscp_wake_lock();
        is_uscp_mode = TRUE;
        gpio_set_value(di->gpio_uscp, GPIO_HIGH);/*open mosfet*/
        pr_info("pull up gpio_uscp!gpio value:%d\n",gpio_value);
    } else if (tdiff <= di->close_mosfet_temp) {
        if (is_uscp_mode) {
            gpio_set_value(di->gpio_uscp, GPIO_LOW);/*close mosfet*/
            msleep(SLEEP_10MS);
            charge_set_hiz_enable(HIZ_DISABLE);
            is_hiz_mode = NOT_HIZ_MODE;
            pr_info("pull down gpio_uscp!\n");
        }
        if(is_hiz_mode){
            charge_set_hiz_enable(HIZ_DISABLE);
            is_hiz_mode = NOT_HIZ_MODE;
            pr_info("disable charge hiz!\n");
        }
        pr_info("pull down gpio_uscp!gpio value:%d\n",gpio_value);
    } else {
        /*do nothing*/
    }
}
static void check_temperature(struct uscp_device_info* di)
{
    int tusb = 0;
    int tbatt = 0;
    int tdiff = 0;

    if(NULL == di)
    {
        pr_err(" %s di is NULL!\n",__func__);
        return;
    }

    tusb = get_usb_temp_value();
    tbatt = get_batt_temp_value();

    pr_info("tusb = %d, tbatt = %d\n", tusb, tbatt);
    tdiff = tusb - tbatt;
    if(INVALID_BATT_TEMP == tbatt)
    {
        tdiff = INVALID_DELTA_TEMP;
        pr_err("get battery adc temp err,not care!!!\n");
    }

	if (di->dmd_hiz_enable) {
		if ((tusb >= di->uscp_threshold_tusb) && (tdiff >= di->open_hiz_temp)) {
			if (protect_dmd_notify_enable_hiz) {
				if (!dsm_client_ocuppy(uscp_client)) {
					pr_info("record and notify open hiz temp\n");
					dsm_client_record(uscp_client, "usb short happened,open hiz!\n");
					dsm_client_notify(uscp_client, ERROR_NO_USB_SHORT_PROTECT_HIZ);
					protect_dmd_notify_enable_hiz = DMD_NOTIFY_HIZ_DISABLE;
				}
			}
		}
	}

	if ((tusb >= di->uscp_threshold_tusb) && (tdiff >= di->open_mosfet_temp)) {
		if (protect_dmd_notify_enable) {
			if (!dsm_client_ocuppy(uscp_client)) {
				pr_info("record and notify\n");
				dsm_client_record(uscp_client, "usb short happened,tusb = %d,tbatt = %d\n",
					tusb,tbatt);
				dsm_client_notify(uscp_client, ERROR_NO_USB_SHORT_PROTECT);
				protect_dmd_notify_enable = 0;
			}
		}
	}

    set_interval(di, tdiff);
    protection_process(di, tbatt, tusb);
}
static void uscp_check_work(struct work_struct *work)
{
    struct uscp_device_info *di = NULL;
    int interval = 0;
    int type = 0;

#ifdef CONFIG_HLTHERM_RUNTEST
    pr_info("Disable HLTHERM protect\n");
    return;
#endif

    if (!work) {
        pr_err("%s: invalid param, fatal error\n", __func__);
        return;
    }

    di = container_of(work,struct uscp_device_info, uscp_check_wk);
    if (!di) {
        pr_err("%s: cannot get uscp device info, fatal error\n", __func__);
        return;
    }

    type = get_propety_int(di->usb_psy, POWER_SUPPLY_PROP_TYPE);

    if (((USCP_DEFAULT_CHK_CNT == di->keep_check_cnt) && (POWER_SUPPLY_TYPE_UNKNOWN == type)))
    {
        protect_dmd_notify_enable = TRUE;
        gpio_set_value(di->gpio_uscp, GPIO_LOW);//close mosfet
        di->keep_check_cnt = USCP_DEFAULT_CHK_CNT;
        di->check_interval = NORMAL_MONITOR_INTERVAL;
        is_uscp_mode = FALSE;
        di->keep_check_cnt = USCP_INSERT_CHG_CNT;
        pr_info("chargertype is %d,stop checking\n", type);
        return;
    }

    check_temperature(di);
    interval = di->check_interval;

    hrtimer_start(&di->timer, ktime_set(interval/MSEC_PER_SEC, (interval % MSEC_PER_SEC) * USEC_PER_SEC), HRTIMER_MODE_REL);

}

static enum hrtimer_restart uscp_timer_func(struct hrtimer *timer)
{
    struct uscp_device_info *di = NULL;

    if (!timer) {
        pr_err("%s: invalid paral, fatal error\n", __func__);
        return HRTIMER_NORESTART;
    }

    di = container_of(timer, struct uscp_device_info, timer);
    queue_work(di->uscp_wq, &di->uscp_check_wk);
    return HRTIMER_NORESTART;
}

static void check_ntc_error(void)
{
    int temp = 0;
    int sum = 0;
    int i = 0;

    for (i = 0; i < USB_TEMP_CNT; ++i)
    {
        sum += get_usb_temp_value();
    }
    temp = sum / USB_TEMP_CNT;
    if (temp > TUSB_TEMP_UPPER_LIMIT || temp < TUSB_TEMP_LOWER_LIMIT)
    {
        if (!dsm_client_ocuppy(uscp_client))
        {
            pr_info("ntc error notify\n");
            dsm_client_record(uscp_client, "ntc error happened!\n");
            dsm_client_notify(uscp_client, ERROR_NO_USB_SHORT_PROTECT_NTC);
        }
        protect_enable = FALSE;
    }
    else
    {
        pr_info("enable usb short protect\n");
        protect_enable = TRUE;
    }

}

static int uscp_power_get_property(struct power_supply *psy,
				enum power_supply_property psp,
				union power_supply_propval *val)
{
	return 0;

}
static int uscp_power_set_property(struct power_supply *psy,
				enum power_supply_property psp,
				const union power_supply_propval *val)
{
	return 0;

}
static int uscp_notifier_call(struct notifier_block *nb, unsigned long event, void *data)
{
	struct uscp_device_info *chip = container_of(nb, struct uscp_device_info, nb);
	int present = 0;

	if(!chip)
		return NOTIFY_OK;
	present = ((int)event);
	pr_info("uscp usb_present=%d\n",present);
	charge_type_handler(chip,present);


	return NOTIFY_OK;
}



static int uscp_probe(struct platform_device *pdev)
{
    struct device_node* np = NULL;
    struct uscp_device_info* di = NULL;
    enum power_supply_type type = POWER_SUPPLY_TYPE_UNKNOWN;
    struct power_supply *usb_psy = NULL;
    struct power_supply *batt_psy = NULL;
    struct power_supply *bms_psy = NULL;
    int ret = 0;
    int batt_present = TRUE;
    int need_uscp = TRUE;

    if (!pdev) {
        pr_err("%s: invalid param, fatal error\n", __func__);
        return -EINVAL;
    }

    usb_psy = power_supply_get_by_name("usb");
    if (!usb_psy) {
        pr_err("usb supply not found deferring probe\n");
        return -EPROBE_DEFER;
    }
    batt_psy = power_supply_get_by_name("battery");
    if (!batt_psy) {
        pr_err("batt supply not found deferring probe\n");
        return -EPROBE_DEFER;
    }
    bms_psy = power_supply_get_by_name("bms");
    if (!bms_psy) {
        pr_err("bms supply not found deferring probe\n");
        return -EPROBE_DEFER;
    }

    np = pdev->dev.of_node;
    if(NULL == np)
    {
        pr_err("np is NULL\n");
        return -1;
    }

    di = kzalloc(sizeof(*di), GFP_KERNEL);
    if (!di)
    {
        pr_err("di is NULL\n");
        return -ENOMEM;

    }
    di->dev = &pdev->dev;
    dev_set_drvdata(&(pdev->dev), di);
    g_di = di;
    if (!uscp_client)
    {
        uscp_client = dsm_register_client(&dsm_uscp);
    }
    if (NULL == uscp_client)
    {
        pr_err("uscp register dsm fail\n");
        ret = -EINVAL;
        goto free_mem;
    }

    di->usb_psy = usb_psy;
    di->batt_psy = batt_psy;
    di->bms_psy = bms_psy;
    is_uscp_mode = FALSE;
    di->keep_check_cnt = USCP_INSERT_CHG_CNT;

    di->gpio_uscp = of_get_named_gpio(np, "gpio_usb_short_circuit_protect",0);
    if (!gpio_is_valid(di->gpio_uscp))
    {
        pr_err("gpio_uscp is not valid\n");
        ret = -EINVAL;
        goto free_mem;
    }
    pr_info("gpio_uscp = %d\n", di->gpio_uscp);
    di->np_node = of_parse_phandle(np, "qcom,uscp-vadc", 0);
    if (!di->np_node) {
        dev_err(di->dev, "Missing adc-vadc config\n");
        ret = -EINVAL;
        goto free_mem;
    }
    if (!huawei_adc_init_done(di->np_node)) {
        dev_err(di->dev, "huawei adc not init yet, defer\n");
        ret = -EPROBE_DEFER;
        goto free_mem;
    }

	di->switch_mode = of_property_read_bool(np,
						"is_switch_mode");

    ret = gpio_request(di->gpio_uscp, "usb_short_circuit_protect");
    if (ret)
    {
        pr_err("could not request gpio_uscp\n");
        ret = -EINVAL;
        goto free_mem;
    }
    gpio_direction_output(di->gpio_uscp, GPIO_LOW);

    ret = of_property_read_u32(np, "no_need_uscp", &(di->no_need_uscp));
    if (ret)
    {
        pr_err("get open_mosfet_temp info fail!\n");
        ret = -EINVAL;
        goto free_gpio;
    }
    pr_info("no_need_uscp = %d\n", di->no_need_uscp);
    ret = of_property_read_u32(np, "uscp_threshold_tusb", &(di->uscp_threshold_tusb));
    if (ret)
    {
        di->uscp_threshold_tusb = DEFAULT_TUSB_THRESHOLD;
        pr_err("get uscp_threshold_tusb info fail!use default threshold = %d\n",di->uscp_threshold_tusb);
    }
    pr_info("uscp_threshold_tusb = %d\n", di->uscp_threshold_tusb);
    ret = of_property_read_u32(np, "open_mosfet_temp", &(di->open_mosfet_temp));
    if (ret)
    {
        pr_err("get open_mosfet_temp info fail!\n");
        ret = -EINVAL;
        goto free_gpio;
    }
    pr_info("open_mosfet_temp = %d\n", di->open_mosfet_temp);
    ret = of_property_read_u32(np, "close_mosfet_temp", &(di->close_mosfet_temp));
    if (ret)
    {
        pr_err("get close_mosfet_temp info fail!\n");
        ret = -EINVAL;
        goto free_gpio;
    }
    pr_info("close_mosfet_temp = %d\n", di->close_mosfet_temp);
    ret = of_property_read_u32(np, "interval_switch_temp", &(di->interval_switch_temp));
    if (ret)
    {
        pr_err("get interval_switch_temp info fail!\n");
        ret = -EINVAL;
        goto free_gpio;
    }
    pr_info("interval_switch_temp = %d\n", di->interval_switch_temp);

	ret = of_property_read_u32(np, "open_hiz_temp", &(di->open_hiz_temp));
    if (ret)
    {
        di->open_hiz_temp = di->open_mosfet_temp;
        pr_err("get open_hiz_temp info fail,use default open_mosfet_temp!\n");
    }

    pr_info("open_hiz_temp = %d\n", di->open_hiz_temp);

	ret = of_property_read_u32(np, "dmd_hiz_enable", &(di->dmd_hiz_enable));
	 if (ret)
	 {
		di->dmd_hiz_enable = DMD_HIZ_DISABLE;
		pr_err("get dmd_hiz_enable info fail,use value zero!\n");
	 }
	 pr_info("dmd_hiz_enable = %d\n", di->dmd_hiz_enable);

    check_ntc_error();
    batt_present = get_propety_int(batt_psy, POWER_SUPPLY_PROP_PRESENT);

    if((is_factory_mode)&& (di->no_need_uscp == TRUE))
    {
        need_uscp = FALSE; //qcom not need uscp in factory mode
    }

   if ((!batt_present) ) {
        pr_err("battery is not exist or no need uscp in factory mode, disable usb short protect!\n");
        protect_enable = FALSE;
    }
    if (!protect_enable)
    {
        goto free_gpio;
    }
    wake_lock_init(&uscp_wakelock, WAKE_LOCK_SUSPEND, "usb_short_circuit_protect_wakelock");
    di->uscp_wq = create_singlethread_workqueue("usb_short_circuit_protect_wq");
    INIT_WORK(&di->uscp_check_wk, uscp_check_work);
    hrtimer_init(&di->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    di->timer.function = uscp_timer_func;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
	di->uscp_psy.name		= "uscp";
	di->uscp_psy.type		= POWER_SUPPLY_TYPE_UNKNOWN;
	di->uscp_psy.get_property	= uscp_power_get_property;
	di->uscp_psy.set_property	= uscp_power_set_property;
	di->uscp_psy.supplied_from  = uscp_power_supplied_from;
	di->uscp_psy.num_supplies = ARRAY_SIZE(uscp_power_supplied_from);
	di->uscp_psy.properties	= NULL;
	di->uscp_psy.num_properties	= 0;
	di->uscp_psy.external_power_changed = uscp_external_power_changed;
	di->uscp_psy.property_is_writeable = NULL;
	ret = power_supply_register(di->dev, &di->uscp_psy);
#else
	di->nb.notifier_call = uscp_notifier_call;
	ret = usb_charger_register_notifier(&di->nb);
#endif
	if (ret < 0) {
		pr_err("Unable to register batt_psy rc = %d\n", ret);
		goto free_gpio;
	}

    type = get_propety_int(usb_psy, POWER_SUPPLY_PROP_TYPE);
	di->usb_present = get_propety_int(di->usb_psy, POWER_SUPPLY_PROP_PRESENT);

    pr_info("usb type = %d present=%d\n", type,di->usb_present);
    charge_type_handler(di, di->usb_present);

    pr_info("uscp probe ok!\n");
    return 0;

free_gpio:
  gpio_free(di->gpio_uscp);
free_mem:
    kfree(di);
    g_di = NULL;
    return ret;
}
static int uscp_remove(struct platform_device *pdev)
{
    struct uscp_device_info *di = NULL;

    if (!pdev) {
        pr_err("%s: invalid param, fatal error\n", __func__);
        return -EINVAL;
    }

    di = dev_get_drvdata(&pdev->dev);
    if (!di) {
        pr_err("%s: Cannot get uscp device info, fatal error\n", __func__);
        return -ENODEV;
    }

    gpio_free(di->gpio_uscp);
	usb_charger_notifier_unregister(&di->nb);
    kfree(di);
    g_di = NULL;

    return 0;
}
#ifndef CONFIG_HLTHERM_RUNTEST
#ifdef CONFIG_PM
static int usb_short_circuit_protect_suspend(struct platform_device *pdev, pm_message_t state)
{
    struct uscp_device_info* di = platform_get_drvdata(pdev);
    if((NULL == di)||(protect_enable == FALSE))
    {
        pr_info("%s:di is NULL\n", __func__);
        return 0;
    }
    pr_info("%s:+\n", __func__);
    cancel_work_sync(&di->uscp_check_wk);
    hrtimer_cancel(&di->timer);
    pr_info("%s:-\n", __func__);
    return 0;
}
static int usb_short_circuit_protect_resume(struct platform_device *pdev)
{
    struct uscp_device_info* di = platform_get_drvdata(pdev);
    if((NULL == di)||(protect_enable == FALSE))
    {
        pr_info("%s:di is NULL\n", __func__);
        return 0;
    }
	di->usb_present = get_propety_int(di->usb_psy, POWER_SUPPLY_PROP_PRESENT);
    if( FALSE == di->usb_present  )
    {
        pr_info("%s:di->usb_present = %d\n", __func__,di->usb_present);
        return 0;
    }
    pr_info("%s:+ di->usb_present = %d\n", __func__,di->usb_present);
    queue_work(di->uscp_wq, &di->uscp_check_wk);
    pr_info("%s:-\n", __func__);
    return 0;
}
#endif
#endif
static struct of_device_id uscp_match_table[] =
{
    {
        .compatible = "huawei,usb_short_circuit_protect",
        .data = NULL,
    },
    {
    },
};
static struct platform_driver uscp_driver = {
    .probe = uscp_probe,
#ifndef CONFIG_HLTHERM_RUNTEST
#ifdef CONFIG_PM
    /*depend on IPC driver,so we set SR suspend/resume and IPC is suspend_late/early_resume*/
    .suspend = usb_short_circuit_protect_suspend,
    .resume = usb_short_circuit_protect_resume,
#endif
#endif
	.remove = uscp_remove,
    .driver = {
        .name = "huawei,usb_short_circuit_protect",
        .owner = THIS_MODULE,
        .of_match_table = of_match_ptr(uscp_match_table),
    },
};

static int __init uscp_init(void)
{
    return platform_driver_register(&uscp_driver);
}

device_initcall_sync(uscp_init);

static void __exit uscp_exit(void)
{
    platform_driver_unregister(&uscp_driver);
}

module_exit(uscp_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:uscp");
MODULE_AUTHOR("HUAWEI Inc");
