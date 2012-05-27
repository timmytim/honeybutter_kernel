/*
 *  linux/drivers/char/resetlog.c
 *
 *  Copyright (C) 2010  Pegatron
 *
 *  Added resetlog support.
 *    Dec-14-2010, Morris Teng <morris_teng@pegatroncorp.com>
 */

#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/raw.h>
#include <linux/tty.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/crash_dump.h>
#include <linux/backing-dev.h>
#include <linux/bootmem.h>
#include <linux/splice.h>
#include <linux/pfn.h>
#include <linux/smp_lock.h>

#include <linux/io.h>

#include <linux/reboot.h>
#include <linux/delay.h>

#define RESETOG_SIG_SIZE	8
const unsigned char ucaSigCmp[RESETOG_SIG_SIZE] = {
	'r', 'e', 's', 'e', 't', 'l', 'o', 'g' };

typedef struct _resetlog {
	unsigned char	ucaSig[RESETOG_SIG_SIZE];
	unsigned int	dPanic;
	unsigned int	dSize;
	unsigned int	dCount;
	unsigned int	dRead;
	unsigned int	dWrite;
	char		*pcBuf;
} RESETLOG;

static RESETLOG *s_pRamLog = (RESETLOG *)-1;
static RESETLOG *s_pResetLog = (RESETLOG *)-1;

static inline unsigned int IsLogEmpty(RESETLOG *pMsgLog)
{
	return ((pMsgLog->dRead + 1) == pMsgLog->dWrite) ? 1 : 0;
}

static inline unsigned int IsLogFull(RESETLOG *pMsgLog)
{
	return (pMsgLog->dRead == pMsgLog->dWrite) ? 1 : 0;
}

static inline unsigned int LogSize(RESETLOG *pMsgLog)
{
	unsigned int dRead;
	unsigned int dWrite;
	unsigned int dSize;

	dRead = pMsgLog->dRead;
	dWrite = pMsgLog->dWrite;

	if (dRead < dWrite)
		dSize = dWrite - dRead;
	else
		dSize = dWrite + pMsgLog->dSize - dRead;
	return dSize - 1;
}

int BackupResetLog(RESETLOG *pMsgLog, char *pbDest, unsigned int cbSize)
{
	unsigned int cbLogSize;
	unsigned int idxRead, idxRealRead;
	unsigned int cbPart1;
	unsigned int cbToCopy;

	if (!pbDest || cbSize == 0)
		return 0;

	if (IsLogEmpty(pMsgLog))
		return 0;

	cbLogSize = LogSize(pMsgLog);
	idxRead = pMsgLog->dRead;

	if (cbSize > cbLogSize)
		cbSize = cbLogSize;

	cbToCopy = cbSize;

	cbPart1 = pMsgLog->dSize - idxRead - 1;

	if (cbPart1 != 0 && cbPart1 <= cbToCopy) {
		memcpy(pbDest, &pMsgLog->pcBuf[idxRead + 1], cbPart1);
		pbDest += cbPart1;

		cbToCopy -= cbPart1;
		idxRead += cbPart1;
	}

	if (cbToCopy) {
		idxRealRead = idxRead + 1;
		if (idxRealRead >= pMsgLog->dSize)
			idxRealRead = 0;
		memcpy(pbDest, &pMsgLog->pcBuf[idxRealRead], cbToCopy);
		idxRead += cbToCopy;
		if (idxRead >= pMsgLog->dSize)
			idxRead = idxRead - pMsgLog->dSize;
	}

	pMsgLog->dRead = idxRead;

	return cbSize;
}

void ResetLogEmitChar(char ch)
{
	if ((int)s_pRamLog == -1 || ch == 0)
		return;

	if (IsLogFull(s_pRamLog)) {
		/* no free buffer available, overwrite previous data */
		s_pRamLog->dRead += 1;
		if (s_pRamLog->dRead >= s_pRamLog->dSize)
			s_pRamLog->dRead = 0;
	}

	s_pRamLog->pcBuf[s_pRamLog->dWrite] = ch;
	s_pRamLog->dWrite++;
	s_pRamLog->dCount++;
	if (s_pRamLog->dWrite >= s_pRamLog->dSize)
		s_pRamLog->dWrite = 0;
}
EXPORT_SYMBOL(ResetLogEmitChar);

int log_buf_copy(char *dest, int idx, int len);
int InitResetLog(void)
{
	RESETLOG *p = NULL;
	int idx = 0;
	char c;

	if ((int)s_pRamLog != -1) {
		printk(KERN_INFO "InitResetLog abort %.8x\n",
			(unsigned int)s_pRamLog);
		return 0;
	}

	p = (RESETLOG *)IO_LOG_VIRT;
	printk(KERN_INFO "InitResetLog-1 %.8x\n", (unsigned int)p);
	printk(KERN_INFO "InitResetLog-2 %.8x, %.8x, %.8x, %.8x, %.8x\n",
		*(unsigned int *)&p->ucaSig[0],
		*(unsigned int *)&p->ucaSig[4],
		p->dPanic, p->dSize, p->dCount);

	if (!memcmp(p->ucaSig, ucaSigCmp, 8)) {
		s_pResetLog = (RESETLOG *)(IO_LOG_VIRT + (IO_LOG_SIZE >> 1));
		memcpy(s_pResetLog, p, sizeof(RESETLOG));
		s_pResetLog->pcBuf = (char *)(s_pResetLog + 1);
		s_pResetLog->dCount = BackupResetLog(p, s_pResetLog->pcBuf,
							s_pResetLog->dSize);
	}
	memset(p, 0, IO_LOG_SIZE >> 1);
	memcpy(p->ucaSig, ucaSigCmp, RESETOG_SIG_SIZE);

	p->pcBuf = (char *)(p + 1);
	p->dSize = (IO_LOG_SIZE >> 1) - sizeof(RESETLOG);
	p->dPanic = 0;

	p->dRead = 0;
	p->dWrite = 1;

	p->dCount = 0;

	printk(KERN_INFO "InitResetLog-3 %.8x, %.8x, %.8x, %.8x, %.8x, %.8x\n",
		*(unsigned int *)&p->ucaSig[0],
		*(unsigned int *)&p->ucaSig[4],
		(unsigned int)p->pcBuf, p->dPanic, p->dSize, p->dCount);

	idx = log_buf_copy(p->pcBuf + p->dWrite, 0, p->dSize - 1);
	if (idx > 0) {
		p->dWrite += idx;
		if (p->dWrite >= p->dSize)
			p->dWrite = 0;
		printk(KERN_INFO "InitResetLog-4 %d chars\n", idx);
		while (log_buf_copy(&c, idx, 1) == 1) {
			ResetLogEmitChar(c);
			idx++;
		}
	} else {
		printk(KERN_INFO "InitResetLog-5 %d chars (%s)\n",
			idx, p->pcBuf + p->dWrite);
	}
	s_pRamLog = p;
	return 1;
}

unsigned int IsResetLog(void)
{
	return s_pResetLog != (RESETLOG *)-1 ? 1 : 0;
}

unsigned int IsPanic(void)
{
	if ((int)s_pResetLog != -1)
		return s_pResetLog->dPanic ? 1 : 0;
	else
		return 0;
}

void ResetlogSetPanic(void)
{
	if ((int)s_pRamLog != -1)
		s_pRamLog->dPanic = 0xffffffff;
}
EXPORT_SYMBOL(ResetlogSetPanic);

unsigned int ReadResetLog(
	char __user *pbDest, unsigned int cbSize, loff_t *ppos)
{
	unsigned int dByteToRead;

	if ((int)s_pResetLog == -1)
		return 0;

	if (*ppos >= s_pResetLog->dCount)
		return 0;

	dByteToRead = s_pResetLog->dCount - *ppos;
	if (cbSize > dByteToRead)
		cbSize = dByteToRead;
	copy_to_user(pbDest, s_pResetLog->pcBuf + *ppos, cbSize);
	return cbSize;
}

static ssize_t ramlog_read(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	size_t written;
	char *tmp;

	if (!count)
		return 0;

	if (!access_ok(VERIFY_WRITE, buf, count))
		return -EFAULT;

	tmp = kmalloc(count + 1, GFP_KERNEL);
	if (tmp == NULL)
		return -ENOMEM;
	written = 0;
	written = ReadResetLog(buf, count, ppos);
	*ppos += written;
	kfree(tmp);
	return written ? written : 0;
}


static ssize_t resetlog_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	char *tmp;
	ssize_t ret;

	tmp = kmalloc(count + 1, GFP_KERNEL);
	if (tmp == NULL)
		return -ENOMEM;
	ret = -EFAULT;
	if (!copy_from_user(tmp, buf, count))
		tmp[count] = 0;
	if (strstr(tmp, "reboot")) {
		int i;

		printk(KERN_INFO "ramlog_write going to reboot\n");
		for (i = 0; i < 5000; ) {
			mdelay(1);
			i++;
		}
		emergency_restart();
	} else if (strstr(tmp, "panic"))
		panic("Panic from ramlog write");
	kfree(tmp);
	return ret;
}

static ssize_t resetlog_read(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	if (!count)
		return 0;

	if (!access_ok(VERIFY_WRITE, buf, count))
		return -EFAULT;

	return ramlog_read(file, buf, count, ppos);
}
static const struct file_operations resetlog_fops = {
	.read		= resetlog_read,
	.write		= resetlog_write,
};

static ssize_t paniclog_read(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	if (!count)
		return 0;

	if (!access_ok(VERIFY_WRITE, buf, count))
		return -EFAULT;

	return ramlog_read(file, buf, count, ppos);
}
static const struct file_operations paniclog_fops = {
	.read		= paniclog_read,
};

#define MEM_NAME_RESETLOG	"resetlog"
#define MEM_NAME_PANICLOG	"paniclog"

static struct miscdevice misc_resetlog_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "resetlog",
	.fops = &resetlog_fops
};

static struct miscdevice misc_paniclog_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "paniclog",
	.fops = &paniclog_fops
};

int resetlog_enabled = 0;
static int __init resetlog_enable_log(char *str)
{
    resetlog_enabled = 1;
    return 1;
}
__setup("resetlog_enable", resetlog_enable_log);


static int __init ramlog_dev_init(void)
{
    if (resetlog_enabled) {
        if (InitResetLog() == 0) {
            pr_err("%s fail to init resetlog\n", __func__);
            return -1;
        }
        if (misc_register(&misc_resetlog_dev))
            pr_err("%s error registering %s\n", __func__,
                   misc_resetlog_dev.name);

        if (IsPanic())
            if (misc_register(&misc_paniclog_dev))
                pr_err("%s error registering %s\n", __func__,
                       misc_paniclog_dev.name);
    }

	return 0;
}
fs_initcall(ramlog_dev_init);

