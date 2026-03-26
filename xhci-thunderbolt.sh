#!/bin/bash
# Unbind/rebind xhci_hcd from Thunderbolt USB controllers around suspend.
# TB NHI is blacklisted, so PCIe tunnel can't be re-established on resume.
# Without this, xhci_hcd wastes ~11s on "setup device" timeouts.
TB_XHCI="0000:09:00.0 0000:7f:00.0"

case $1 in
    pre)
        for dev in $TB_XHCI; do
            [ -e /sys/bus/pci/drivers/xhci_hcd/$dev ] && \
                echo $dev > /sys/bus/pci/drivers/xhci_hcd/unbind 2>/dev/null
        done
        ;;
    post)
        for dev in $TB_XHCI; do
            [ ! -e /sys/bus/pci/drivers/xhci_hcd/$dev ] && \
                echo $dev > /sys/bus/pci/drivers/xhci_hcd/bind 2>/dev/null
        done
        ;;
esac
