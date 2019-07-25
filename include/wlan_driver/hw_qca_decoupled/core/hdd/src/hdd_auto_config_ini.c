#ifdef CONFIG_HUAWEI_WIFI
#include <hdd_auto_config_ini.h>
/**------------------------------------------------------------------------
  \brief construct_configini_with_ini_type() -construct wlan configini file path
         with pubfd which is defined in the dtsi
  \sa
  -------------------------------------------------------------------------*/
int construct_configini_with_ini_type(char *configini_path) {
	const char *ini_type = NULL;
	char configini_path_with_ini_type[NVBIN_PATH_LENTH] = {0};

	ini_type = get_hw_wifi_ini_type();
	if( NULL != ini_type ) {
		pr_info("%s ini_type:%s;\n", __func__,ini_type);
	} else {
		pr_err("%s get ini_type failed, using %s;\n", __func__,WLAN_INI_FILE);
		return -1;
	}
	strncpy(configini_path_with_ini_type, "../../vendor/etc/wifi/WCNSS_qcom_cfg_",
		NVBIN_PATH_LENTH - 1);
	pr_info("%s line:%d construct_configini_with_ini_type:%s;\n",
		__func__,__LINE__,configini_path_with_ini_type);
	strncat(configini_path_with_ini_type,ini_type,NVBIN_PATH_LENTH - 1);
	pr_info("%s line:%d construct_configini_with_ini_type:%s;\n",
		__func__,__LINE__,configini_path_with_ini_type);
	strncat(configini_path_with_ini_type,".ini",NVBIN_PATH_LENTH - 1);
	pr_info("%s line:%d construct_configini_with_ini_type:%s;\n",
		__func__,__LINE__,configini_path_with_ini_type);
	strncpy(configini_path,configini_path_with_ini_type,NVBIN_PATH_LENTH - 1);
	return 0;
}

QDF_STATUS hdd_auto_config_ini(const struct firmware **fw, hdd_context_t *pHddCtx) {
	int status = QDF_STATUS_E_FAILURE;
	char configini_path_with_ini_type[NVBIN_PATH_LENTH] = {0};
	int ret;

	ret = construct_configini_with_ini_type(configini_path_with_ini_type);
	if(!ret) {
		status = request_firmware(fw, configini_path_with_ini_type, pHddCtx->parent_dev);
		if(!status)
			pr_info("wcnss: %s:download firmware_path %s successed;\n",
				__func__, configini_path_with_ini_type);

        } else if (status || !*fw || !((struct firmware *)*fw)->data || !((struct firmware *)*fw)->size) {
		hdd_err("wcnss: %s: request_firmware failed for %s (status = %d)\n",
			__func__, configini_path_with_ini_type, status);
                status = request_firmware(fw, WLAN_INI_FILE, pHddCtx->parent_dev);
		if (status) {
			hdd_err("%s: request_firmware failed %d",__func__, status);
			return QDF_STATUS_E_FAILURE;
		} else if(!*fw || !((struct firmware *)*fw)->data || !((struct firmware *)*fw)->size) {
			hdd_err("%s: %s download failed",__func__, WLAN_INI_FILE);
			return QDF_STATUS_E_FAILURE;
		}else{
			hdd_err("wcnss: %s:download firmware_path %s successed;\n",
			__func__, WLAN_INI_FILE);
		}
	}

	return status;
}
#endif
