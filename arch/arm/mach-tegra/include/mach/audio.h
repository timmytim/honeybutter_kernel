/*
 * arch/arm/mach-tegra/include/mach/audio.h
 *
 * Copyright (C) 2010 Google, Inc.
 *
 * Author:
 *	Iliyan Malchev <malchev@google.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __ARCH_ARM_MACH_TEGRA_AUDIO_H
#define __ARCH_ARM_MACH_TEGRA_AUDIO_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/regulator/consumer.h>
#include <mach/i2s.h>

#define FIFO1		0
#define FIFO2		1

/* FIXME: this is not enforced by the hardware. */
#define I2S_FIFO_TX             FIFO1
#define I2S_FIFO_RX             FIFO2

#define TEGRA_AUDIO_ENABLE_TX	1
#define TEGRA_AUDIO_ENABLE_RX	2

#define AUDIO_TX_MODE 1
#define AUDIO_RX_MODE 2

struct tegra_audio_platform_data {
	bool i2s_master;
	bool dsp_master;
	int i2s_master_clk; /* When I2S mode and master, the framesync rate. */
	int dsp_master_clk; /* When DSP mode and master, the framesync rate. */
	bool dma_on;
	unsigned long i2s_clk_rate;
	unsigned long spdif_clk_rate;
	const char *dap_clk;
	const char *audio_sync_clk;

	int mode; /* I2S, LJM, RJM, etc. */
	int fifo_fmt;
	int bit_size;
	int i2s_bus_width; /* 32-bit for 16-bit packed I2S */
	int dsp_bus_width; /* 16-bit for DSP data format */
	int mask; /* enable tx and rx? */
	bool stereo_capture; /* True if hardware supports stereo */
	bool en_dmic; /* True if digital mic is default*/
	void *driver_data;
};

struct tegra_wired_jack_conf {
	int hp_det_n;   /* headphone jack detection gpio pin */
	int en_mic_ext; /* external mic enable gpio pin */
	int en_mic_int; /* internal mic enable gpio pin */
	int cdc_irq;    /* mic jack detection pin(IRQ-mode or generic gpio) */
	int en_spkr;    /* gpio pin to drive amplifier */
	int en_spk_ext;
	int en_spk_int;
	int ext_hp_det;
	const char *spkr_amp_reg;    /* regulator name for speaker amp */
	struct regulator *amp_reg;   /* regulator for speaker amp */
};

#endif /* __ARCH_ARM_MACH_TEGRA_AUDIO_H */
