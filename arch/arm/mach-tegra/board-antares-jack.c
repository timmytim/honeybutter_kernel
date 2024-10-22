/*
 * arch/arm/mach-tegra/board-antares-jack.c
 *
 * Copyright (c) 2011, NVIDIA Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/platform_device.h>
#include <sound/jack.h>
#include <sound/soc.h>
#include <mach/gpio.h>
#include <linux/regulator/consumer.h>
#include <mach/audio.h>

#include "gpio-names.h"
#include "board-antares.h"

static struct tegra_wired_jack_conf antares_wr_jack_conf = {
	.hp_det_n = TEGRA_GPIO_PW2,
	.en_mic_ext = TEGRA_GPIO_PX1,
	//.en_mic_int = TEGRA_GPIO_PX0,
	.en_spkr = WM8903_GP3,
	.cdc_irq = TEGRA_GPIO_PX0,
	.en_spk_ext = TEGRA_GPIO_PL7,
	.en_spk_int = TEGRA_GPIO_PL6,
	.ext_hp_det = TEGRA_GPIO_PL0,
	.spkr_amp_reg = "avdd_amp"
};

static struct platform_device antares_hs_jack_device = {
	.name = "tegra_wired_jack",
	.id = -1,
	.dev = {
		.platform_data = &antares_wr_jack_conf,
	},
};

int __init antares_wired_jack_init(void)
{
	int ret;

	tegra_gpio_enable(antares_wr_jack_conf.hp_det_n);
	//tegra_gpio_enable(antares_wr_jack_conf.en_mic_int);
	tegra_gpio_enable(antares_wr_jack_conf.en_mic_ext);
	tegra_gpio_enable(antares_wr_jack_conf.cdc_irq);
	tegra_gpio_enable(antares_wr_jack_conf.en_spk_ext);
	tegra_gpio_enable(antares_wr_jack_conf.en_spk_int);
	tegra_gpio_enable(antares_wr_jack_conf.ext_hp_det);

	ret = platform_device_register(&antares_hs_jack_device);
	return ret;
}
