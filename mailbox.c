#include "mailbox.h"
#include <linux/atomic.h>
#include "apple_bce.h"
#include <linux/version.h>

#define REG_MBOX_OUT_BASE 0x820
#define REG_MBOX_REPLY_COUNTER 0x108
#define REG_MBOX_REPLY_BASE 0x810
#define REG_TIMESTAMP_BASE 0xC000

#define BCE_MBOX_TIMEOUT_MS 3000  /* macOS uses 3s per attempt (clock_deadline_for_jiffies(3, 1e9)) */
#define BCE_MBOX_MAX_ATTEMPTS 6   /* macOS retries up to 6 times (18s total worst case) */

/* Check if the PCI device is still reachable by reading vendor ID.
 * Returns true if alive, false if device is gone (0xFFFFFFFF). */
static bool bce_pci_is_alive(struct pci_dev *pci)
{
    u32 val;
    if (pci_read_config_dword(pci, PCI_VENDOR_ID, &val))
        return false;
    return val != 0xFFFFFFFF;
}

void bce_mailbox_init(struct bce_mailbox *mb, void __iomem *reg_mb, struct pci_dev *pci)
{
    mb->reg_mb = reg_mb;
    mb->pci = pci;
    init_completion(&mb->mb_completion);
}

int bce_mailbox_send(struct bce_mailbox *mb, u64 msg, u64* recv)
{
    u32 __iomem *regb;
    int attempt;

    if (!bce_pci_is_alive(mb->pci)) {
        pr_err("apple-bce: mailbox_send: device gone before send (msg %llx)\n", msg);
        return -ENODEV;
    }

    if (atomic_cmpxchg(&mb->mb_status, 0, 1) != 0) {
        return -EEXIST; // We don't support two messages at once
    }

    regb = (u32*) ((u8*) mb->reg_mb + REG_MBOX_OUT_BASE);

    for (attempt = 0; attempt < BCE_MBOX_MAX_ATTEMPTS; attempt++) {
        reinit_completion(&mb->mb_completion);

        if (!bce_pci_is_alive(mb->pci)) {
            pr_err("apple-bce: mailbox_send: device gone during attempt %d (msg %llx)\n",
                   attempt + 1, msg);
            atomic_set(&mb->mb_status, 0);
            return -ENODEV;
        }

        pr_debug("bce_mailbox_send: %llx (attempt %d/%d)\n",
                 msg, attempt + 1, BCE_MBOX_MAX_ATTEMPTS);
        iowrite32((u32) msg, regb);
        iowrite32((u32) (msg >> 32), regb + 1);
        iowrite32(0, regb + 2);
        iowrite32(0, regb + 3);

        wait_for_completion_timeout(&mb->mb_completion,
                                    msecs_to_jiffies(BCE_MBOX_TIMEOUT_MS));

        if (atomic_read(&mb->mb_status) == 2)
            goto got_reply;
    }

    pr_err("bce_mailbox_send: timeout after %d attempts for msg %llx\n",
           BCE_MBOX_MAX_ATTEMPTS, msg);
    atomic_set(&mb->mb_status, 0);
    return -ETIMEDOUT;

got_reply:
    *recv = mb->mb_result;
    pr_debug("bce_mailbox_send: reply %llx\n", *recv);

    atomic_set(&mb->mb_status, 0);
    return 0;
}

int bce_mailbox_send_poll(struct bce_mailbox *mb, u64 msg, u64 *recv,
                          unsigned long timeout_ms)
{
    u32 __iomem *regb_out;
    u32 __iomem *regb_in;
    u32 res, lo, hi;
    unsigned long deadline;
    int attempt;

    if (!bce_pci_is_alive(mb->pci)) {
        pr_err("apple-bce: mailbox_send_poll: device gone\n");
        return -ENODEV;
    }

    regb_out = (u32 *) ((u8 *) mb->reg_mb + REG_MBOX_OUT_BASE);

    for (attempt = 0; attempt < 3; attempt++) {
        /* Send the message */
        iowrite32((u32) msg, regb_out);
        iowrite32((u32) (msg >> 32), regb_out + 1);
        iowrite32(0, regb_out + 2);
        iowrite32(0, regb_out + 3);

        /* Poll the reply counter — no IRQ needed */
        deadline = jiffies + msecs_to_jiffies(timeout_ms);
        while (time_before(jiffies, deadline)) {
            res = ioread32((u8 *) mb->reg_mb + REG_MBOX_REPLY_COUNTER);
            if (res == 0xFFFFFFFF)
                return -ENODEV;
            if (((res >> 20) & 0xf) > 0) {
                /* Got a reply — read it */
                regb_in = (u32 *) ((u8 *) mb->reg_mb + REG_MBOX_REPLY_BASE);
                lo = ioread32(regb_in);
                hi = ioread32(regb_in + 1);
                ioread32(regb_in + 2);
                ioread32(regb_in + 3);
                *recv = ((u64) hi << 32) | lo;
                pr_info("apple-bce: mbox poll RX: type=0x%x value=0x%llx\n",
                        (u32)(*recv >> 58), *recv & 0x3FFFFFFFFFFFFFFLL);
                return 0;
            }
            usleep_range(100, 500);
        }
        pr_warn("apple-bce: mailbox_send_poll: timeout attempt %d\n", attempt + 1);
    }

    return -ETIMEDOUT;
}

int bce_mailbox_wait_unsolicited(struct bce_mailbox *mb, u64 *recv, unsigned long timeout_ms)
{
    if (atomic_cmpxchg(&mb->mb_status, 0, 1) != 0)
        return -EBUSY;

    reinit_completion(&mb->mb_completion);

    wait_for_completion_timeout(&mb->mb_completion,
                                msecs_to_jiffies(timeout_ms));

    if (atomic_read(&mb->mb_status) == 2) {
        *recv = mb->mb_result;
        atomic_set(&mb->mb_status, 0);
        return 0;
    }

    atomic_set(&mb->mb_status, 0);
    return -ETIMEDOUT;
}

static int bce_mailbox_retrive_response(struct bce_mailbox *mb)
{
    u32 __iomem *regb;
    u32 lo, hi;
    int count, counter;
    u32 res;

    if (!bce_pci_is_alive(mb->pci))
        return -ENODEV;

    res = ioread32((u8*) mb->reg_mb + REG_MBOX_REPLY_COUNTER);
    if (res == 0xFFFFFFFF)
        return -ENODEV;
    count = (res >> 20) & 0xf;
    counter = count;
    pr_debug("bce_mailbox_retrive_response count=%i\n", count);
    while (counter--) {
        regb = (u32*) ((u8*) mb->reg_mb + REG_MBOX_REPLY_BASE);
        lo = ioread32(regb);
        hi = ioread32(regb + 1);
        ioread32(regb + 2);
        ioread32(regb + 3);
        mb->mb_result = ((u64) hi << 32) | lo;
        pr_emerg("apple-bce: mbox RX: raw=0x%llx type=0x%x value=0x%llx\n",
                 mb->mb_result, (u32)(mb->mb_result >> 58),
                 mb->mb_result & 0x3FFFFFFFFFFFFFFLL);
    }
    return count > 0 ? 0 : -ENODATA;
}

int bce_mailbox_handle_interrupt(struct bce_mailbox *mb)
{
    int status = bce_mailbox_retrive_response(mb);
    if (!status) {
        /* Only signal completion if a synchronous send is waiting (status==1).
         * Responses to fire-and-forget messages (status==0) are silently consumed. */
        if (atomic_cmpxchg(&mb->mb_status, 1, 2) == 1)
            complete(&mb->mb_completion);
    }
    return status;
}

int bce_mailbox_send_noreply(struct bce_mailbox *mb, u64 msg)
{
    u32 __iomem *regb;

    if (!bce_pci_is_alive(mb->pci)) {
        pr_err("apple-bce: mailbox_send_noreply: device gone (msg %llx)\n", msg);
        return -ENODEV;
    }

    regb = (u32*) ((u8*) mb->reg_mb + REG_MBOX_OUT_BASE);
    pr_debug("bce_mailbox_send_noreply: %llx\n", msg);
    iowrite32((u32) msg, regb);
    iowrite32((u32) (msg >> 32), regb + 1);
    iowrite32(0, regb + 2);
    iowrite32(0, regb + 3);
    /* No wait — fire-and-forget. Any T2 response consumed by IRQ handler. */
    return 0;
}

static void bc_send_timestamp(struct timer_list *tl);

void bce_timestamp_init(struct bce_timestamp *ts, void __iomem *reg)
{
    u32 __iomem *regb;

    spin_lock_init(&ts->stop_sl);
    ts->stopped = false;

    ts->reg = reg;

    regb = (u32*) ((u8*) ts->reg + REG_TIMESTAMP_BASE);

    ioread32(regb);
    mb();

    timer_setup(&ts->timer, bc_send_timestamp, 0);
}

void bce_timestamp_start(struct bce_timestamp *ts, bool is_initial)
{
    unsigned long flags;
    u32 __iomem *regb = (u32*) ((u8*) ts->reg + REG_TIMESTAMP_BASE);

    if (is_initial) {
        iowrite32((u32) -4, regb + 2);
        iowrite32((u32) -1, regb);
    } else {
        iowrite32((u32) -3, regb + 2);
        iowrite32((u32) -1, regb);
    }

    spin_lock_irqsave(&ts->stop_sl, flags);
    ts->stopped = false;
    spin_unlock_irqrestore(&ts->stop_sl, flags);
    mod_timer(&ts->timer, jiffies + msecs_to_jiffies(150));
}

void bce_timestamp_stop(struct bce_timestamp *ts, struct pci_dev *pci)
{
    unsigned long flags;
    u32 __iomem *regb = (u32*) ((u8*) ts->reg + REG_TIMESTAMP_BASE);

    spin_lock_irqsave(&ts->stop_sl, flags);
    ts->stopped = true;
    spin_unlock_irqrestore(&ts->stop_sl, flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)
    del_timer_sync(&ts->timer);
#else
    timer_delete_sync(&ts->timer);
#endif
    if (bce_pci_is_alive(pci)) {
        iowrite32((u32) -2, regb + 2);
        iowrite32((u32) -1, regb);
    } else {
        pr_err("apple-bce: timestamp_stop: device gone, skipping MMIO\n");
    }
}

static void bc_send_timestamp(struct timer_list *tl)
{
    struct bce_timestamp *ts;
    unsigned long flags;
    u32 __iomem *regb;
    ktime_t bt;

    ts = container_of(tl, struct bce_timestamp, timer);
    regb = (u32*) ((u8*) ts->reg + REG_TIMESTAMP_BASE);
    local_irq_save(flags);
    ioread32(regb + 2);
    mb();
    bt = ktime_get_boottime();
    iowrite32((u32) bt, regb + 2);
    iowrite32((u32) (bt >> 32), regb);

    spin_lock(&ts->stop_sl);
    if (!ts->stopped)
        mod_timer(&ts->timer, jiffies + msecs_to_jiffies(150));
    spin_unlock(&ts->stop_sl);
    local_irq_restore(flags);
}
