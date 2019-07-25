#include <linux/bootdevice.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define	ANDROID_BOOT_DEV_MAX	50
static char android_boot_dev[ANDROID_BOOT_DEV_MAX];
static int __init get_android_boot_dev(char *str)
{
	strlcpy(android_boot_dev, str, ANDROID_BOOT_DEV_MAX);
	return 1;
}
__setup("androidboot.bootdevice=", get_android_boot_dev);
static int get_bootdevice_type_from_cmdline(void)
{
	int type;
	if (strnstr(android_boot_dev, "sdhci", strlen(android_boot_dev))) {
		type = 0;
	} else if (strnstr(android_boot_dev, "ufshc", strlen(android_boot_dev))) {
		type = 1;
	} else {
		type = -1;
	}
	return type;
}
static int __init bootdevice_init(void)
{
	int err;
	enum bootdevice_type type;

	type = get_bootdevice_type_from_cmdline();
	if (-1 == type) {
		err = -ENODEV;
		goto out;
	}
	pr_info("storage bootdevice: %s\n",
		type == BOOT_DEVICE_EMMC ? "eMMC" : "UFS");

	err = 0;

out:
	set_bootdevice_type(type);
	return err;
}
arch_initcall(bootdevice_init);
