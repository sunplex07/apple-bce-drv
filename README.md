# T2 Resume Speed Scripts

systemd-sleep scripts for MacBook Pro T2 machines running Linux.
Install to `/usr/lib/systemd/system-sleep/` and `chmod +x`.

## ht-suspend.sh
Offlines HT sibling CPUs (7-11) before suspend and re-onlines them
async after resume. Saves ~5.3s of resume time — HT siblings take
~1s each to bring online after S3 on Coffee Lake.

## xhci-thunderbolt.sh
Unbinds xhci_hcd from Thunderbolt USB controllers before suspend
and rebinds after resume. Thunderbolt NHI is blacklisted so the
PCIe tunnel can't be re-established — without this, xhci wastes
~7s on setup device timeouts trying to enumerate dead tunnels.
