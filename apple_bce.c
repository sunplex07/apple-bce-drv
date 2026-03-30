#include "apple_bce.h"
#include <linux/module.h>
#include <linux/crc32.h>
#include <linux/fs.h>
#include "audio/audio.h"
#include "vhci/command.h"
#include <linux/version.h>


static dev_t bce_chrdev;
static struct class *bce_class;

struct apple_bce_device *global_bce;

static bool send_restore_no_state = true;

#define KBD_BL_PATH "/sys/class/leds/:white:kbd_backlight/brightness"

static int saved_kbd_brightness = -1;

static int bce_read_sysfs_int(const char *path)
{
    struct file *f;
    char buf[16] = {};
    int val = -1;
    loff_t pos = 0;

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f))
        return -1;
    kernel_read(f, buf, sizeof(buf) - 1, &pos);
    filp_close(f, NULL);
    if (kstrtoint(strim(buf), 10, &val))
        return -1;
    return val;
}

static void bce_write_sysfs_int(const char *path, int val)
{
    struct file *f;
    char buf[16];
    int len;
    loff_t pos = 0;

    f = filp_open(path, O_WRONLY, 0);
    if (IS_ERR(f))
        return;
    len = snprintf(buf, sizeof(buf), "%d\n", val);
    kernel_write(f, buf, len, &pos);
    filp_close(f, NULL);
}


static int bce_create_command_queues(struct apple_bce_device *bce);
static void bce_free_command_queues(struct apple_bce_device *bce);
static irqreturn_t bce_handle_mb_irq(int irq, void *dev);
static irqreturn_t bce_handle_dma_irq(int irq, void *dev);
static int bce_fw_version_handshake(struct apple_bce_device *bce);
static int bce_register_command_queue(struct apple_bce_device *bce, struct bce_queue_memcfg *cfg, int is_sq);

static int apple_bce_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    struct apple_bce_device *bce = NULL;
    int status = 0;
    int nvec;

    pr_info("apple-bce: capturing our device\n");

    if (pci_enable_device(dev))
        return -ENODEV;
    if (pci_request_regions(dev, "apple-bce")) {
        status = -ENODEV;
        goto fail;
    }
    pci_set_master(dev);
    nvec = pci_alloc_irq_vectors(dev, 1, 8, PCI_IRQ_MSI);
    if (nvec < 5) {
        status = -EINVAL;
        goto fail;
    }

    bce = kzalloc(sizeof(struct apple_bce_device), GFP_KERNEL);
    if (!bce) {
        status = -ENOMEM;
        goto fail;
    }

    bce->pci = dev;
    pci_set_drvdata(dev, bce);

    bce->devt = bce_chrdev;
    bce->dev = device_create(bce_class, &dev->dev, bce->devt, NULL, "apple-bce");
    if (IS_ERR_OR_NULL(bce->dev)) {
        status = PTR_ERR(bce_class);
        goto fail;
    }

    bce->reg_mem_mb = pci_iomap(dev, 4, 0);
    bce->reg_mem_dma = pci_iomap(dev, 2, 0);

    if (IS_ERR_OR_NULL(bce->reg_mem_mb) || IS_ERR_OR_NULL(bce->reg_mem_dma)) {
        dev_warn(&dev->dev, "apple-bce: Failed to pci_iomap required regions\n");
        goto fail;
    }

    bce_mailbox_init(&bce->mbox, bce->reg_mem_mb, bce->pci);
    bce_timestamp_init(&bce->timestamp, bce->reg_mem_mb);

    spin_lock_init(&bce->queues_lock);
    ida_init(&bce->queue_ida);

    if ((status = pci_request_irq(dev, 0, bce_handle_mb_irq, NULL, dev, "bce_mbox")))
        goto fail;
    if ((status = pci_request_irq(dev, 4, NULL, bce_handle_dma_irq, dev, "bce_dma")))
        goto fail_interrupt_0;

    if ((status = dma_set_mask_and_coherent(&dev->dev, DMA_BIT_MASK(37)))) {
        dev_warn(&dev->dev, "dma: Setting mask failed\n");
        goto fail_interrupt;
    }

    /* Gets the function 0's interface. This is needed because Apple only accepts DMA on our function if function 0
       is a bus master, so we need to work around this. */
    bce->pci0 = pci_get_slot(dev->bus, PCI_DEVFN(PCI_SLOT(dev->devfn), 0));
#ifndef WITHOUT_NVME_PATCH
    if ((status = pci_enable_device_mem(bce->pci0))) {
        dev_warn(&dev->dev, "apple-bce: failed to enable function 0\n");
        goto fail_dev0;
    }
#endif
    pci_set_master(bce->pci0);

    bce_timestamp_start(&bce->timestamp, true);

    if ((status = bce_fw_version_handshake(bce)))
        goto fail_ts;
    pr_info("apple-bce: handshake done\n");

    if (send_restore_no_state) {
        u64 resp;
        if ((status = bce_mailbox_send(&bce->mbox,
                BCE_MB_MSG(BCE_MB_RESTORE_NO_STATE, 0), &resp))) {
            pr_err("apple-bce: probe: RESTORE_NO_STATE failed (%d)\n", status);
            goto fail_ts;
        }
        pr_info("apple-bce: probe: RESTORE_NO_STATE OK\n");
    }

    if ((status = bce_create_command_queues(bce))) {
        pr_info("apple-bce: Creating command queues failed\n");
        goto fail_ts;
    }

    global_bce = bce;

    bce_vhci_create(bce, &bce->vhci);

    return 0;

fail_ts:
    bce_timestamp_stop(&bce->timestamp, bce->pci);
#ifndef WITHOUT_NVME_PATCH
    pci_disable_device(bce->pci0);
fail_dev0:
#endif
    pci_dev_put(bce->pci0);
fail_interrupt:
    pci_free_irq(dev, 4, dev);
fail_interrupt_0:
    pci_free_irq(dev, 0, dev);
fail:
    if (bce && bce->dev) {
        device_destroy(bce_class, bce->devt);

        if (!IS_ERR_OR_NULL(bce->reg_mem_mb))
            pci_iounmap(dev, bce->reg_mem_mb);
        if (!IS_ERR_OR_NULL(bce->reg_mem_dma))
            pci_iounmap(dev, bce->reg_mem_dma);

        kfree(bce);
    }

    pci_free_irq_vectors(dev);
    pci_release_regions(dev);
    pci_disable_device(dev);

    if (!status)
        status = -EINVAL;
    return status;
}

static int bce_create_command_queues(struct apple_bce_device *bce)
{
    int status;
    struct bce_queue_memcfg *cfg;

    bce->cmd_cq = bce_alloc_cq(bce, 0, 0x20);
    bce->cmd_cmdq = bce_alloc_cmdq(bce, 1, 0x20);
    if (bce->cmd_cq == NULL || bce->cmd_cmdq == NULL) {
        status = -ENOMEM;
        goto err;
    }
    bce->queues[0] = (struct bce_queue *) bce->cmd_cq;
    bce->queues[1] = (struct bce_queue *) bce->cmd_cmdq->sq;

    cfg = kzalloc(sizeof(struct bce_queue_memcfg), GFP_KERNEL);
    if (!cfg) {
        status = -ENOMEM;
        goto err;
    }
    bce_get_cq_memcfg(bce->cmd_cq, cfg);
    if ((status = bce_register_command_queue(bce, cfg, false)))
        goto err;
    bce_get_sq_memcfg(bce->cmd_cmdq->sq, bce->cmd_cq, cfg);
    if ((status = bce_register_command_queue(bce, cfg, true)))
        goto err;
    kfree(cfg);

    return 0;

err:
    if (bce->cmd_cq)
        bce_free_cq(bce, bce->cmd_cq);
    if (bce->cmd_cmdq)
        bce_free_cmdq(bce, bce->cmd_cmdq);
    return status;
}

static void bce_free_command_queues(struct apple_bce_device *bce)
{
    bce_free_cq(bce, bce->cmd_cq);
    bce_free_cmdq(bce, bce->cmd_cmdq);
    bce->cmd_cq = NULL;
    bce->queues[0] = NULL;
}

static irqreturn_t bce_handle_mb_irq(int irq, void *dev)
{
    struct apple_bce_device *bce = pci_get_drvdata(dev);
    bce_mailbox_handle_interrupt(&bce->mbox);
    return IRQ_HANDLED;
}

static irqreturn_t bce_handle_dma_irq(int irq, void *dev)
{
    int i;
    struct apple_bce_device *bce = pci_get_drvdata(dev);
    spin_lock(&bce->queues_lock);
    for (i = 0; i < BCE_MAX_QUEUE_COUNT; i++)
        if (bce->queues[i] && bce->queues[i]->type == BCE_QUEUE_CQ)
            bce_handle_cq_completions(bce, (struct bce_queue_cq *) bce->queues[i]);
    spin_unlock(&bce->queues_lock);
    return IRQ_HANDLED;
}

static int bce_fw_version_handshake(struct apple_bce_device *bce)
{
    u64 result;
    int status;

    if ((status = bce_mailbox_send(&bce->mbox, BCE_MB_MSG(BCE_MB_SET_FW_PROTOCOL_VERSION, BC_PROTOCOL_VERSION),
            &result)))
        return status;
    if (BCE_MB_TYPE(result) != BCE_MB_SET_FW_PROTOCOL_VERSION ||
        BCE_MB_VALUE(result) != BC_PROTOCOL_VERSION) {
        pr_err("apple-bce: FW version handshake failed %x:%llx\n", BCE_MB_TYPE(result), BCE_MB_VALUE(result));
        return -EINVAL;
    }
    return 0;
}

static int bce_register_command_queue(struct apple_bce_device *bce, struct bce_queue_memcfg *cfg, int is_sq)
{
    int status;
    int cmd_type;
    u64 result;
    // OS X uses an bidirectional direction, but that's not really needed
    dma_addr_t a = dma_map_single(&bce->pci->dev, cfg, sizeof(struct bce_queue_memcfg), DMA_TO_DEVICE);
    if (dma_mapping_error(&bce->pci->dev, a))
        return -ENOMEM;
    cmd_type = is_sq ? BCE_MB_REGISTER_COMMAND_SQ : BCE_MB_REGISTER_COMMAND_CQ;
    status = bce_mailbox_send(&bce->mbox, BCE_MB_MSG(cmd_type, a), &result);
    dma_unmap_single(&bce->pci->dev, a, sizeof(struct bce_queue_memcfg), DMA_TO_DEVICE);
    if (status)
        return status;
    if (BCE_MB_TYPE(result) != BCE_MB_REGISTER_COMMAND_QUEUE_REPLY)
        return -EINVAL;
    return 0;
}

static void apple_bce_remove(struct pci_dev *dev)
{
    struct apple_bce_device *bce = pci_get_drvdata(dev);
    bce->is_being_removed = true;

    bce_vhci_destroy(&bce->vhci);

    bce_timestamp_stop(&bce->timestamp, bce->pci);
#ifndef WITHOUT_NVME_PATCH
    pci_disable_device(bce->pci0);
#endif
    pci_dev_put(bce->pci0);
    pci_free_irq(dev, 0, dev);
    pci_free_irq(dev, 4, dev);
    bce_free_command_queues(bce);
    pci_iounmap(dev, bce->reg_mem_mb);
    pci_iounmap(dev, bce->reg_mem_dma);
    device_destroy(bce_class, bce->devt);
    pci_free_irq_vectors(dev);
    pci_release_regions(dev);
    pci_disable_device(dev);
    kfree(bce);
}

static int bce_save_state_and_sleep(struct apple_bce_device *bce)
{
    int attempt, status = 0;
    u64 resp;
    dma_addr_t dma_addr;
    void *dma_ptr = NULL;
    size_t size = max(PAGE_SIZE, 4096UL);

    pr_info("apple-bce: suspend: entering bce_save_state_and_sleep\n");

    /* Fire-and-forget pre-signal: tells T2 to prepare for state serialization.
     * macOS sends this before the synchronous SAVE_STATE_AND_SLEEP (0x17). */
    bce_mailbox_send_noreply(&bce->mbox, BCE_MB_MSG(BCE_MB_SAVE_STATE, 0));
    pr_info("apple-bce: suspend: pre-signal sent\n");

    for (attempt = 0; attempt < 5; ++attempt) {
        pr_info("apple-bce: suspend: attempt %i, buffer size %zu\n", attempt, size);
        dma_ptr = dma_alloc_coherent(&bce->pci->dev, size, &dma_addr, GFP_KERNEL);
        if (!dma_ptr) {
            pr_err("apple-bce: suspend failed (data alloc failed)\n");
            break;
        }
        if ((dma_addr % 4096) != 0) {
            pr_err("apple-bce: suspend: unaligned DMA addr %pad\n", &dma_addr);
            dma_free_coherent(&bce->pci->dev, size, dma_ptr, dma_addr);
            return -EINVAL;
        }
        pr_info("apple-bce: suspend: sending SAVE_STATE_AND_SLEEP (dma=%pad size=%zu)\n",
                &dma_addr, size);
        status = bce_mailbox_send(&bce->mbox,
                BCE_MB_MSG(BCE_MB_SAVE_STATE_AND_SLEEP, (dma_addr & ~(4096LLU - 1)) | (size / 4096)), &resp);
        if (status) {
            pr_err("apple-bce: suspend failed (mailbox send, status=%d)\n", status);
            break;
        }
        pr_info("apple-bce: suspend: T2 responded type=0x%x value=0x%llx\n",
                BCE_MB_TYPE(resp), BCE_MB_VALUE(resp));
        if (BCE_MB_TYPE(resp) == BCE_MB_SAVE_RESTORE_STATE_COMPLETE) {
            bce->saved_data_dma_addr = dma_addr;
            bce->saved_data_dma_ptr = dma_ptr;
            bce->saved_data_dma_size = size;
            pr_info("apple-bce: suspend: state saved successfully\n");
            return 0;
        } else if (BCE_MB_TYPE(resp) == BCE_MB_SAVE_STATE_AND_SLEEP_FAILURE) {
            size_t new_size;
            dma_free_coherent(&bce->pci->dev, size, dma_ptr, dma_addr);
            dma_ptr = NULL;
            /* The 0x10ff magic value was extracted from Apple's driver */
            new_size = (BCE_MB_VALUE(resp) + 0x10ff) & ~(4096LLU - 1);
            /* macOS validates: new > old AND < 1MB+1 (prevents infinite loop / OOM) */
            if (new_size <= size || new_size > 0x100001) {
                pr_err("apple-bce: suspend: invalid resize request %zu (was %zu)\n",
                       new_size, size);
                status = -EINVAL;
                break;
            }
            size = new_size;
            pr_debug("apple-bce: suspend: device requested a larger buffer (%zu)\n", size);
            continue;
        } else {
            pr_err("apple-bce: suspend failed (invalid device response)\n");
            status = -EINVAL;
            break;
        }
    }
    if (dma_ptr)
        dma_free_coherent(&bce->pci->dev, size, dma_ptr, dma_addr);
    /* Abort: tell T2 to restore its own state (fire-and-forget, matching macOS).
     * macOS aborts suspend when the state buffer cannot be allocated. */
    bce_mailbox_send_noreply(&bce->mbox, BCE_MB_MSG(BCE_MB_SLEEP_NO_STATE, 0));
    return status ? status : -ENOMEM;
}

static int bce_restore_state_and_wake(struct apple_bce_device *bce)
{
    int status;
    u64 resp;
    if (!bce->saved_data_dma_ptr) {
        if ((status = bce_mailbox_send(&bce->mbox, BCE_MB_MSG(BCE_MB_RESTORE_NO_STATE, 0), &resp))) {
            pr_err("apple-bce: resume with no state failed (mailbox send)\n");
            return status;
        }
        if (BCE_MB_TYPE(resp) != BCE_MB_RESTORE_NO_STATE) {
            pr_err("apple-bce: resume with no state failed (invalid device response)\n");
            return -EINVAL;
        }
        return 0;
    }

    if ((status = bce_mailbox_send(&bce->mbox, BCE_MB_MSG(BCE_MB_RESTORE_STATE_AND_WAKE,
            (bce->saved_data_dma_addr & ~(4096LLU - 1)) | (bce->saved_data_dma_size / 4096)), &resp))) {
        pr_err("apple-bce: resume with state failed (mailbox send)\n");
        goto try_no_state;
    }
    if (BCE_MB_TYPE(resp) != BCE_MB_SAVE_RESTORE_STATE_COMPLETE) {
        pr_err("apple-bce: resume with state failed (invalid device response)\n");
        goto try_no_state;
    }
    /* State restore succeeded */
    dma_free_coherent(&bce->pci->dev, bce->saved_data_dma_size, bce->saved_data_dma_ptr, bce->saved_data_dma_addr);
    bce->saved_data_dma_ptr = NULL;
    return 0;

try_no_state:
    /* State restore failed — T2 may have cold-booted.
     * Free the (now useless) state buffer and try stateless recovery. */
    dma_free_coherent(&bce->pci->dev, bce->saved_data_dma_size, bce->saved_data_dma_ptr, bce->saved_data_dma_addr);
    bce->saved_data_dma_ptr = NULL;
    pr_warn("apple-bce: attempting stateless resume (RESTORE_NO_STATE)\n");
    if ((status = bce_mailbox_send(&bce->mbox, BCE_MB_MSG(BCE_MB_RESTORE_NO_STATE, 0), &resp))) {
        pr_err("apple-bce: stateless resume also failed (mailbox send)\n");
        return status;
    }
    if (BCE_MB_TYPE(resp) != BCE_MB_RESTORE_NO_STATE) {
        pr_err("apple-bce: stateless resume failed (invalid device response)\n");
        return -EINVAL;
    }
    pr_warn("apple-bce: stateless resume succeeded — T2 likely rebooted\n");
    return 0;
}

/*
 * Hard teardown: full PCI-level shutdown.  Tears down everything that
 * remove() does EXCEPT: bce struct, PCI regions, iomapped BARs, and
 * sysfs/chardev entries.  The goal is to make the PCI core see a fully
 * quiesced device so it can enter D3cold — matching what happens when
 * the driver is unbound via rmmod.
 *
 * Kept alive across suspend (no need to redo on reinit):
 *   - bce struct (kzalloc'd once in probe)
 *   - pci_request_regions (BAR claims — driver stays bound)
 *   - pci_iomap BAR4/BAR2 (virtual mappings survive D3cold because
 *     pci_restore_state() rewrites the same BAR addresses)
 *   - device_create / chardev (sysfs entries)
 *   - pci0 reference (pci_get_slot — slot doesn't change)
 */
static void apple_bce_hard_teardown(struct apple_bce_device *bce)
{
    struct pci_dev *dev = bce->pci;

    pr_info("apple-bce: hard teardown: destroying VHCI\n");
    bce->is_being_removed = true;
    bce_vhci_destroy(&bce->vhci);

    pr_info("apple-bce: hard teardown: stopping timestamp + freeing queues\n");
    bce_timestamp_stop(&bce->timestamp, bce->pci);
    bce_free_command_queues(bce);

    pr_info("apple-bce: hard teardown: freeing IRQs + MSI vectors\n");
    pci_free_irq(dev, 0, dev);
    pci_free_irq(dev, 4, dev);
    pci_free_irq_vectors(dev);

    pr_info("apple-bce: hard teardown: disabling bus master + device\n");
    pci_clear_master(dev);
#ifndef WITHOUT_NVME_PATCH
    /* Only touch pci0 if we own it (no nvme driver on function 0) */
    pci_clear_master(bce->pci0);
    pci_disable_device(bce->pci0);
#endif
    pci_disable_device(dev);

    bce->is_being_removed = false;
    pr_info("apple-bce: hard teardown: complete — device fully quiesced\n");
}

/*
 * Hard re-init: full PCI-level bringup.  Redoes everything that probe()
 * does EXCEPT the resources kept alive by hard_teardown (struct, regions,
 * iomaps, sysfs).  This is the resume counterpart of hard_teardown.
 *
 * The PCI core has already called pci_restore_state() by the time we
 * get here (.resume runs after .resume_noirq), so config space / BARs
 * are restored and the device is in D0.
 */
static int apple_bce_hard_reinit(struct apple_bce_device *bce)
{
    struct pci_dev *dev = bce->pci;
    int status;
    int nvec;

    pr_info("apple-bce: hard reinit: starting\n");

    /* Clear the teardown flag so queue destroy paths during USB reset
     * cycles will properly ida_free() qids and reuse them. Without this,
     * qids leak and the T2 rejects registration at higher indices. */
    bce->is_being_removed = false;

    /* --- PCI-level bringup (matches probe order) --- */
    if ((status = pci_enable_device(dev))) {
        pr_err("apple-bce: hard reinit: pci_enable_device failed (%d)\n", status);
        return status;
    }
    pci_set_master(dev);

    nvec = pci_alloc_irq_vectors(dev, 1, 8, PCI_IRQ_MSI);
    if (nvec < 5) {
        pr_err("apple-bce: hard reinit: MSI alloc failed (got %d)\n", nvec);
        status = -EINVAL;
        goto fail_disable;
    }

    if ((status = dma_set_mask_and_coherent(&dev->dev, DMA_BIT_MASK(37)))) {
        pr_err("apple-bce: hard reinit: DMA mask failed (%d)\n", status);
        goto fail_msi;
    }

#ifndef WITHOUT_NVME_PATCH
    if ((status = pci_enable_device_mem(bce->pci0))) {
        pr_err("apple-bce: hard reinit: pci0 enable failed (%d)\n", status);
        goto fail_msi;
    }
#endif
    pci_set_master(bce->pci0);

    /* --- IRQ handlers --- */
    if ((status = pci_request_irq(dev, 0, bce_handle_mb_irq, NULL, dev, "bce_mbox"))) {
        pr_err("apple-bce: hard reinit: mbox IRQ failed (%d)\n", status);
        goto fail_pci0;
    }
    if ((status = pci_request_irq(dev, 4, NULL, bce_handle_dma_irq, dev, "bce_dma"))) {
        pr_err("apple-bce: hard reinit: DMA IRQ failed (%d)\n", status);
        goto fail_irq0;
    }

    /* --- Driver-level init (matches probe) --- */
    bce_mailbox_init(&bce->mbox, bce->reg_mem_mb, bce->pci);
    spin_lock_init(&bce->queues_lock);
    ida_init(&bce->queue_ida);
    bce->t2_state_unknown = false;

    bce_timestamp_start(&bce->timestamp, true);

    if ((status = bce_fw_version_handshake(bce))) {
        pr_err("apple-bce: hard reinit: FW handshake failed (%d)\n", status);
        goto fail_ts;
    }
    pr_info("apple-bce: hard reinit: handshake done\n");

    if (send_restore_no_state) {
        u64 resp;
        if ((status = bce_mailbox_send(&bce->mbox,
                BCE_MB_MSG(BCE_MB_RESTORE_NO_STATE, 0), &resp))) {
            pr_err("apple-bce: hard reinit: RESTORE_NO_STATE failed (%d)\n", status);
            goto fail_ts;
        }
        pr_info("apple-bce: hard reinit: RESTORE_NO_STATE OK\n");
    }

    if ((status = bce_create_command_queues(bce))) {
        pr_err("apple-bce: hard reinit: command queues failed (%d)\n", status);
        goto fail_ts;
    }

    bce_vhci_create(bce, &bce->vhci);

    pr_info("apple-bce: hard reinit: complete\n");
    return 0;

fail_ts:
    bce_timestamp_stop(&bce->timestamp, bce->pci);
    pci_free_irq(dev, 4, dev);
fail_irq0:
    pci_free_irq(dev, 0, dev);
fail_pci0:
#ifndef WITHOUT_NVME_PATCH
    pci_disable_device(bce->pci0);
#endif
fail_msi:
    pci_free_irq_vectors(dev);
fail_disable:
    pci_disable_device(dev);
    return status;
}

static int apple_bce_suspend(struct device *dev)
{
    struct pci_dev *pdev = to_pci_dev(dev);
    struct apple_bce_device *bce = pci_get_drvdata(pdev);

    /* Save keyboard backlight before teardown destroys USB devices.
     * systemd-backlight handles most of this, but as a fallback we
     * also save/restore via sysfs in case systemd isn't present. */
    saved_kbd_brightness = bce_read_sysfs_int(KBD_BL_PATH);

    /* Tear down aaudio first — it depends on our BCE queues */
    aaudio_suspend_teardown();

    pr_info("apple-bce: suspend: full teardown to match stub state\n");

    /*
     * Full teardown — make the device look identical to the stub driver
     * (just claimed, nothing else). is_being_removed stays true through
     * the entire sequence so all destroy paths skip T2 commands.
     *
     * After this, pci_pm_suspend_noirq sees a disabled device with no
     * MSI/IRQs/bus-master — identical to an unbound device. PCI core
     * saves clean state and handles D3 transition naturally.
     */
    bce->is_being_removed = true;

    /* 1. Destroy VHCI — removes USB HCD, drains workqueue, frees all
     *    event + message queues and their DMA buffers */
    bce_vhci_destroy(&bce->vhci);

    /* 2. Stop timestamp timer — no more periodic MMIO writes */
    bce_timestamp_stop(&bce->timestamp, bce->pci);

    /* 3. Free command queues — DMA buffers freed, no T2 unregister */
    bce_free_command_queues(bce);

    /* 4. Free IRQ handlers — no more interrupt processing */
    pci_free_irq(pdev, 0, pdev);
    pci_free_irq(pdev, 4, pdev);

    /* 5. Free MSI vectors — PCI core won't snapshot stale MSI config */
    pci_free_irq_vectors(pdev);

    /* 6. Clear bus master — no more DMA from this device */
    pci_clear_master(pdev);
#ifndef WITHOUT_NVME_PATCH
    pci_clear_master(bce->pci0);
    pci_disable_device(bce->pci0);
#endif

    /* 7. Disable device — matches the fully quiesced stub state */
    pci_disable_device(pdev);

    /* Do NOT call pci_save_state/pci_prepare_to_sleep — let PCI core
     * handle everything in suspend_noirq on this clean device.
     * Do NOT free iomaps, regions, bce struct, or sysfs — keep for reinit. */

    pr_info("apple-bce: suspend: teardown complete\n");
    return 0;
}

static void bce_deferred_reinit_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(bce_reinit_dwork, bce_deferred_reinit_work);

static void bce_deferred_reinit_work(struct work_struct *work)
{
    int status;

    if (!global_bce)
        return;

    pr_info("apple-bce: deferred reinit: starting (200ms after resume)\n");
    status = apple_bce_hard_reinit(global_bce);
    if (status)
        pr_err("apple-bce: deferred reinit: FAILED (%d)\n", status);
    else {
        pr_info("apple-bce: deferred reinit: complete\n");

        /* Reinit aaudio after BCE is ready */
        msleep(100);
        status = aaudio_resume_reinit();
        if (status)
            pr_err("apple-bce: deferred reinit: aaudio reinit FAILED (%d)\n", status);

        /* Wait for VHCI USB devices to finish enumerating, then flush
         * logind's device cache. After VHCI rebuild, all input/LED devices
         * get new sysfs paths. Logind caches old references — FlushDevices
         * forces it to re-scan, which cascades to all DEs (GNOME, KDE, etc.)
         * re-discovering keyboard backlight and input devices. */
        msleep(1000);
        if (saved_kbd_brightness > 0) {
            bce_write_sysfs_int(KBD_BL_PATH, saved_kbd_brightness);
            pr_info("apple-bce: restored kbd backlight: %d\n", saved_kbd_brightness);
            saved_kbd_brightness = -1;
        }
        /* Backlight brightness restoration is handled by:
         * 1. systemd-backlight@ service (auto-saves/restores via udev)
         * 2. Sysfs fallback above (if brightness was > 0)
         * 3. UPower restart via udev rule (99-apple-kbd-backlight.rules)
         *    to force re-discovery of the new LED device after VHCI rebuild */
    }
}

static int apple_bce_resume(struct device *dev)
{
    /* Schedule reinit 200ms after resume completes — late enough that
     * all PCI devices are restored and the T2 PCIe endpoint is ready,
     * but fast enough the user barely notices. */
    pr_info("apple-bce: resume: scheduling deferred reinit (200ms)\n");
    schedule_delayed_work(&bce_reinit_dwork, msecs_to_jiffies(200));
    return 0;
}

static struct pci_device_id apple_bce_ids[  ] = {
        { PCI_DEVICE(PCI_VENDOR_ID_APPLE, 0x1801) },
        { 0, },
};

MODULE_DEVICE_TABLE(pci, apple_bce_ids);

struct dev_pm_ops apple_bce_pci_driver_pm = {
        .prepare = apple_bce_suspend,
        .resume = apple_bce_resume
};
struct pci_driver apple_bce_pci_driver = {
        .name = "apple-bce",
        .id_table = apple_bce_ids,
        .probe = apple_bce_probe,
        .remove = apple_bce_remove,
        .driver = {
                .pm = &apple_bce_pci_driver_pm
        }
};


static int __init apple_bce_module_init(void)
{
    int result;
    if ((result = alloc_chrdev_region(&bce_chrdev, 0, 1, "apple-bce")))
        goto fail_chrdev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
    bce_class = class_create(THIS_MODULE, "apple-bce");
#else
    bce_class = class_create("apple-bce");
#endif
    if (IS_ERR(bce_class)) {
        result = PTR_ERR(bce_class);
        goto fail_class;
    }
    if ((result = bce_vhci_module_init())) {
        pr_err("apple-bce: bce-vhci init failed");
        goto fail_class;
    }

    result = pci_register_driver(&apple_bce_pci_driver);
    if (result)
        goto fail_drv;

    /* aaudio disabled for suspend debugging */
    aaudio_module_init();

    return 0;

fail_drv:
    pci_unregister_driver(&apple_bce_pci_driver);
fail_class:
    class_destroy(bce_class);
fail_chrdev:
    unregister_chrdev_region(bce_chrdev, 1);
    if (!result)
        result = -EINVAL;
    return result;
}
static void __exit apple_bce_module_exit(void)
{
    pci_unregister_driver(&apple_bce_pci_driver);

    aaudio_module_exit();
    bce_vhci_module_exit();
    class_destroy(bce_class);
    unregister_chrdev_region(bce_chrdev, 1);
}

/* DIAG: trigger SAVE_STATE_AND_SLEEP from userspace without actual suspend.
 * Write "1" to /sys/module/apple_bce/parameters/test_t2_sleep
 * Write "2" to send RESTORE_STATE_AND_WAKE (or RESTORE_NO_STATE) afterwards */
static int test_t2_sleep_set(const char *val, const struct kernel_param *kp)
{
    int cmd;
    if (kstrtoint(val, 10, &cmd))
        return -EINVAL;
    if (!global_bce) {
        pr_err("apple-bce: test: no device\n");
        return -ENODEV;
    }
    /* cmd=99: Full hard re-init (post-resume re-enumeration) */
    if (cmd == 99) {
        int status;
        pr_info("apple-bce: sysfs: triggering hard reinit\n");
        status = apple_bce_hard_reinit(global_bce);
        pr_info("apple-bce: sysfs: hard reinit returned %d\n", status);
        return status;

    /* Quick fire: send 0x14 only, return immediately */
    } else if (cmd == 1) {
        pr_emerg("apple-bce: FIRE 0x14 (SLEEP_NO_STATE)\n");
        bce_mailbox_send_noreply(&global_bce->mbox,
                BCE_MB_MSG(BCE_MB_SLEEP_NO_STATE, 0));
        return 0;
    /* Quick fire: send 0x15 only, return immediately */
    } else if (cmd == 2) {
        int status;
        u64 resp;
        pr_emerg("apple-bce: FIRE 0x15 (RESTORE_NO_STATE)\n");
        status = bce_mailbox_send(&global_bce->mbox,
                BCE_MB_MSG(BCE_MB_RESTORE_NO_STATE, 0), &resp);
        if (!status)
            pr_emerg("apple-bce: 0x15 reply type=0x%x value=0x%llx\n",
                     BCE_MB_TYPE(resp), BCE_MB_VALUE(resp));
        else
            pr_emerg("apple-bce: 0x15 failed (%d)\n", status);
        return 0;
    }
    return -EINVAL;
}
static const struct kernel_param_ops test_t2_sleep_ops = {
    .set = test_t2_sleep_set,
};
module_param_cb(test_t2_sleep, &test_t2_sleep_ops, NULL, 0200);
MODULE_PARM_DESC(test_t2_sleep, "99=hard reinit, 1=send 0x14, 2=send 0x15");

module_param(send_restore_no_state, bool, 0644);
MODULE_PARM_DESC(send_restore_no_state, "Send RESTORE_NO_STATE (0x15) at probe and resume (default=1)");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MrARM");
MODULE_DESCRIPTION("Apple BCE Driver");
MODULE_VERSION("0.01");
module_init(apple_bce_module_init);
module_exit(apple_bce_module_exit);
