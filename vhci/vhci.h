#ifndef BCE_VHCI_H
#define BCE_VHCI_H

#include "queue.h"
#include "transfer.h"

struct usb_hcd;
struct bce_queue_cq;

struct bce_vhci_device {
    struct bce_vhci_transfer_queue tq[32];
    u32 tq_mask;
};
#define BCE_VHCI_SYS_EVENT_LOG_SIZE 32

struct bce_vhci {
    struct apple_bce_device *dev;
    dev_t vdevt;
    struct device *vdev;
    struct usb_hcd *hcd;
    struct spinlock hcd_spinlock;
    struct bce_vhci_message_queue msg_commands;
    struct bce_vhci_message_queue msg_system;
    struct bce_vhci_message_queue msg_isochronous;
    struct bce_vhci_message_queue msg_interrupt;
    struct bce_vhci_message_queue msg_asynchronous;
    struct spinlock msg_asynchronous_lock;
    struct bce_vhci_command_queue cq;
    struct bce_queue_cq *ev_cq;
    struct bce_vhci_event_queue ev_commands;
    struct bce_vhci_event_queue ev_system;
    struct bce_vhci_event_queue ev_isochronous;
    struct bce_vhci_event_queue ev_interrupt;
    struct bce_vhci_event_queue ev_asynchronous;
    u16 port_mask;
    u8 port_count;
    u16 port_power_mask;
    bce_vhci_device_t port_to_device[16];
    struct bce_vhci_device *devices[16];
    struct workqueue_struct *tq_state_wq;
    struct work_struct w_fw_events;
    struct work_struct w_port_change;
    struct delayed_work w_dfr_reset;
    struct usb_device *dfr_reset_udev;
    bool dfr_needs_boot_reset;
    unsigned long port_change_pending;
    spinlock_t sys_event_log_lock;
    struct bce_vhci_message sys_event_log[BCE_VHCI_SYS_EVENT_LOG_SIZE];
    u32 sys_event_log_head;
    u32 sys_event_log_count;
};

int __init bce_vhci_module_init(void);
void __exit bce_vhci_module_exit(void);

int bce_vhci_create(struct apple_bce_device *dev, struct bce_vhci *vhci);
void bce_vhci_destroy(struct bce_vhci *vhci);
int bce_vhci_start(struct usb_hcd *hcd);
void bce_vhci_stop(struct usb_hcd *hcd);

struct bce_vhci *bce_vhci_from_hcd(struct usb_hcd *hcd);
void bce_vhci_dump_recent_system_events(struct bce_vhci *vhci, const struct bce_vhci_message *req);

#endif //BCE_VHCI_H
