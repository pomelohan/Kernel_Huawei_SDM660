#ifdef CONFIG_HUAWEI_WIFI
#include <linux/firmware.h>
#include <linux/string.h>
#include <wlan_hdd_includes.h>
#include <wlan_hdd_main.h>
#include <wlan_hdd_assoc.h>
#include <wlan_hdd_cfg.h>
#include <qdf_types.h>
#include <csr_api.h>
#include <wlan_hdd_misc.h>
#include <wlan_hdd_napi.h>
#include <cds_concurrency.h>
#include <linux/ctype.h>

#define NVBIN_PATH_LENTH 70
int construct_configini_with_ini_type(char *configini_path);
const void *get_hw_wifi_ini_type(void);
QDF_STATUS hdd_auto_config_ini(const struct firmware **fw, hdd_context_t *pHddCtx);
#endif
