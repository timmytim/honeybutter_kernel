/*
 * drivers/video/tegra/dc/edid.c
 *
 * Copyright (C) 2010 Google, Inc.
 * Author: Erik Gilling <konkers@android.com>
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

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif
#if defined(DEBUG) || defined(CONFIG_PROC_FS)
#include <linux/seq_file.h>
#endif

#include <linux/fb.h>
#include <linux/i2c.h>
#include <linux/vmalloc.h>

#include "edid.h"

struct tegra_edid {
	struct i2c_client	*client;
	struct i2c_board_info	info;
	int			bus;

	u8			*data;
	unsigned		len;
	u8			support_stereo;
	struct tegra_edid_hdmi_eld		eld;
};

#if defined(DEBUG) || defined(CONFIG_PROC_FS)
static int tegra_edid_show(struct seq_file *s, void *unused)
{
	struct tegra_edid *edid = s->private;
	int i;

	seq_printf(s, "I2C channel %d EDID :\n", edid->bus);
	for (i = 0; i < edid->len; i++) {
		seq_printf(s, " %02x", edid->data[i]);

		if (i % 16 == 15)
			seq_printf(s, "\n");
	}

	return 0;
}
#endif

#ifdef CONFIG_PROC_FS
static int tegra_edid_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tegra_edid_show, PDE(inode)->data);
}

static const struct file_operations tegra_edid_proc_fops = {
	.owner          = THIS_MODULE,
	.open		= tegra_edid_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void tegra_edid_proc_add(struct tegra_edid *edid)
{
	char name[] = "edidX";

	snprintf(name, sizeof(name), "edid%1d", edid->bus);
	proc_create_data(name, S_IRUGO, NULL, &tegra_edid_proc_fops, edid);
}
#endif

#ifdef DEBUG
static char tegra_edid_dump_buff[16 * 1024];

static void tegra_edid_dump(struct tegra_edid *edid)
{
	struct seq_file s;
	int i;
	char c;

	memset(&s, 0x0, sizeof(s));

	s.buf = tegra_edid_dump_buff;
	s.size = sizeof(tegra_edid_dump_buff);
	s.private = edid;

	tegra_edid_show(&s, NULL);

	i = 0;
	while (i < s.count ) {
		if ((s.count - i) > 256) {
			c = s.buf[i + 256];
			s.buf[i + 256] = 0;
			printk("%s", s.buf + i);
			s.buf[i + 256] = c;
		} else {
			printk("%s", s.buf + i);
		}
		i += 256;
	}
}
#endif

static int tegra_edid_read_block(struct tegra_edid *edid, int block, u8 *data)
{
	u8 block_buf[] = {block >> 1};
	u8 cmd_buf[] = {(block & 0x1) * 128};
	int status;
	struct i2c_msg msg[] = {
		{
			.addr = 0x30,
			.flags = 0,
			.len = 1,
			.buf = block_buf,
		},
		{
			.addr = 0x50,
			.flags = 0,
			.len = 1,
			.buf = cmd_buf,
		},
		{
			.addr = 0x50,
			.flags = I2C_M_RD,
			.len = 128,
			.buf = data,
		}};
	struct i2c_msg *m;
	int msg_len;

	if (block > 1) {
		msg_len = 3;
		m = msg;
	} else {
		msg_len = 2;
		m = &msg[1];
	}

	status = i2c_transfer(edid->client->adapter, m, msg_len);

	if (status < 0)
		return status;

	if (status != msg_len)
		return -EIO;

	return 0;
}

int tegra_edid_parse_ext_block(u8 *raw, int idx, struct tegra_edid *edid)
{
	u8 *ptr;
	u8 tmp;
	u8 code;
	int len;
	int i;
	bool basic_audio = false;

	ptr = &raw[0];

	/* If CEA 861 block get info for eld struct */
	if (edid && ptr) {
		if (*ptr <= 3)
			edid->eld.eld_ver = 0x02;
		edid->eld.cea_edid_ver = ptr[1];

		/* check for basic audio support in CEA 861 block */
		if(raw[3] & (1<<6)) {
			/* For basic audio, set spk_alloc to Left+Right.
			 * If there is a Speaker Alloc block this will
			 * get over written with that value */
			basic_audio = true;
		}
	}
	ptr = &raw[4];

	while (ptr < &raw[idx]) {
		tmp = *ptr;
		len = tmp & 0x1f;

		/* HDMI Specification v1.4a, section 8.3.2:
		 * see Table 8-16 for HDMI VSDB format.
		 * data blocks have tags in top 3 bits:
		 * tag code 2: video data block
		 * tag code 3: vendor specific data block
		 */
		code = (tmp >> 5) & 0x7;
		switch (code) {
		case 1:
		{
			edid->eld.sad_count = len;
			edid->eld.conn_type = 0x00;
			edid->eld.support_hdcp = 0x00;
			for (i = 0; (i < len) && (i < ELD_MAX_SAD); i++)
				edid->eld.sad[i] = ptr[i + 1];
			len++;
			ptr += len; /* adding the header */
			/* Got an audio data block so enable audio */
			if(basic_audio == true)
				edid->eld.spk_alloc = 1;
			break;
		}
		/* case 2 is commented out for now */
		case 3:
		{
			int j = 0;

			if ((ptr[1] == 0x03) &&
				(ptr[2] == 0x0c) &&
				(ptr[3] == 0)) {
				edid->eld.port_id[0] = ptr[4];
				edid->eld.port_id[1] = ptr[5];
			}
			if ((len >= 8) &&
				(ptr[1] == 0x03) &&
				(ptr[2] == 0x0c) &&
				(ptr[3] == 0)) {
				j = 8;
				tmp = ptr[j++];
				/* HDMI_Video_present? */
				if (tmp & 0x20) {
					/* Latency_Fields_present? */
					if (tmp & 0x80)
						j += 2;
					/* I_Latency_Fields_present? */
					if (tmp & 0x40)
						j += 2;
					/* 3D_present? */
					if (j <= len && (ptr[j] & 0x80))
						edid->support_stereo = 1;
				}
			}
			if ((len > 5) &&
				(ptr[1] == 0x03) &&
				(ptr[2] == 0x0c) &&
				(ptr[3] == 0)) {

				edid->eld.support_ai = (ptr[6] & 0x80);
			}

			if ((len > 9) &&
				(ptr[1] == 0x03) &&
				(ptr[2] == 0x0c) &&
				(ptr[3] == 0)) {

				edid->eld.aud_synch_delay = ptr[10];
			}
			len++;
			ptr += len; /* adding the header */
			break;
		}
		case 4:
		{
			edid->eld.spk_alloc = ptr[1];
			len++;
			ptr += len; /* adding the header */
			break;
		}
		default:
			len++; /* len does not include header */
			ptr += len;
			break;
		}
	}

	return 0;
}

int tegra_edid_mode_support_stereo(struct fb_videomode *mode)
{
	if (!mode)
		return 0;

	if (mode->xres == 1280 && mode->yres == 720 && mode->refresh == 60)
		return 1;

	if (mode->xres == 1280 && mode->yres == 720 && mode->refresh == 50)
		return 1;

	return 0;
}

int tegra_edid_get_monspecs(struct tegra_edid *edid, struct fb_monspecs *specs)
{
	int i;
	int j;
	int ret;
	int extension_blocks;

	edid->support_stereo = 0;

	ret = tegra_edid_read_block(edid, 0, edid->data);
	if (ret)
		return ret;

	memset(specs, 0x0, sizeof(struct fb_monspecs));
	memset(&edid->eld, 0x0, sizeof(struct tegra_edid_hdmi_eld));
	fb_edid_to_monspecs(edid->data, specs);
	if (specs->modedb == NULL)
		return -EINVAL;
	memcpy(edid->eld.monitor_name, specs->monitor, sizeof(specs->monitor));
	edid->eld.mnl = strlen(edid->eld.monitor_name) + 1;
	edid->eld.product_id[0] = edid->data[0x8];
	edid->eld.product_id[1] = edid->data[0x9];
	edid->eld.manufacture_id[0] = edid->data[0xA];
	edid->eld.manufacture_id[1] = edid->data[0xB];

	extension_blocks = edid->data[0x7e];

	for (i = 1; i <= extension_blocks; i++) {
		ret = tegra_edid_read_block(edid, i, edid->data + i * 128);
		if (ret < 0)
			break;

		if (edid->data[i * 128] == 0x2) {
			fb_edid_add_monspecs(edid->data + i * 128, specs);

			tegra_edid_parse_ext_block(edid->data + i * 128,
					edid->data[i * 128 + 2], edid);

			if (edid->support_stereo) {
				for (j = 0; j < specs->modedb_len; j++) {
					if (tegra_edid_mode_support_stereo(
						&specs->modedb[j]))
						specs->modedb[j].vmode |=
						FB_VMODE_STEREO_FRAME_PACK;
				}
			}
		}
	}

	edid->len = i * 128;

#ifdef DEBUG
	tegra_edid_dump(edid);
#endif

	return 0;
}

int tegra_edid_get_eld(struct tegra_edid *edid,
			struct tegra_edid_hdmi_eld *elddata)
{
	if (!elddata)
		return -EFAULT;

	memcpy(elddata, &edid->eld, sizeof(struct tegra_edid_hdmi_eld));

	return 0;
}

struct tegra_edid *tegra_edid_create(int bus)
{
	struct tegra_edid *edid;
	struct i2c_adapter *adapter;
	int err;

	edid = kzalloc(sizeof(struct tegra_edid), GFP_KERNEL);
	if (!edid)
		return ERR_PTR(-ENOMEM);

	edid->data = vmalloc(SZ_32K);
	if (!edid->data) {
		err = -ENOMEM;
		goto free_edid;
	}
	strlcpy(edid->info.type, "tegra_edid", sizeof(edid->info.type));
	edid->bus = bus;
	edid->info.addr = 0x50;
	edid->info.platform_data = edid;

	adapter = i2c_get_adapter(bus);
	if (!adapter) {
		pr_err("can't get adpater for bus %d\n", bus);
		err = -EBUSY;
		goto free_edid;
	}

	edid->client = i2c_new_device(adapter, &edid->info);
	i2c_put_adapter(adapter);

	if (!edid->client) {
		pr_err("can't create new device\n");
		err = -EBUSY;
		goto free_edid;
	}

#ifdef CONFIG_PROC_FS
	tegra_edid_proc_add(edid);
#endif

	return edid;

free_edid:
	vfree(edid->data);
	kfree(edid);

	return ERR_PTR(err);
}

void tegra_edid_destroy(struct tegra_edid *edid)
{
#ifdef CONFIG_PROC_FS
	char name[] = "edidX";

	snprintf(name, sizeof(name), "edid%1d", edid->bus);
	remove_proc_entry(name, NULL);
#endif
	i2c_release_client(edid->client);
	vfree(edid->data);
	kfree(edid);
}

static const struct i2c_device_id tegra_edid_id[] = {
        { "tegra_edid", 0 },
        { }
};

MODULE_DEVICE_TABLE(i2c, tegra_edid_id);

static struct i2c_driver tegra_edid_driver = {
        .id_table = tegra_edid_id,
        .driver = {
                .name = "tegra_edid",
        },
};

static int __init tegra_edid_init(void)
{
        return i2c_add_driver(&tegra_edid_driver);
}

static void __exit tegra_edid_exit(void)
{
        i2c_del_driver(&tegra_edid_driver);
}

module_init(tegra_edid_init);
module_exit(tegra_edid_exit);
