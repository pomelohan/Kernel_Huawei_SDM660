#
# Makefile for MMC/SD card drivers
#
ifeq ($(CONFIG_FACTORY_ANDROID),true)
KBUILD_CFLAGS += -DEMMC_FMD_FACTORY_MODE
endif

obj-$(CONFIG_MMC_BLOCK)		+= mmc_block.o
mmc_block-objs			:= block.o queue.o
obj-$(CONFIG_MMC_TEST)		+= mmc_test.o

obj-$(CONFIG_SDIO_UART)		+= sdio_uart.o

obj-$(CONFIG_MMC_BLOCK_TEST)		+= mmc_block_test.o
obj-$(CONFIG_HW_SD_HEALTH_DETECT)	+= mmc_health_diag.o
obj-$(CONFIG_HW_EMMC_PROTECT_MODULE)	+= hw_mmc_protect.o
obj-$(CONFIG_MMC_FFU)		+= ffu.o