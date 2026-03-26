#!/bin/bash
# Offline HT siblings before suspend, re-online async after resume.
# Saves ~5.3s of resume time by skipping slow HT core re-init.

HT_CPUS="7 8 9 10 11"

case $1 in
    pre)
        for cpu in $HT_CPUS; do
            echo 0 > /sys/devices/system/cpu/cpu${cpu}/online 2>/dev/null
        done
        ;;
    post)
        # Daemonize so it survives systemd-sleep exiting
        nohup bash -c '
            sleep 1
            for cpu in 7 8 9 10 11; do
                echo 1 > /sys/devices/system/cpu/cpu${cpu}/online 2>/dev/null
            done
        ' </dev/null >/dev/null 2>&1 &
        disown
        ;;
esac
