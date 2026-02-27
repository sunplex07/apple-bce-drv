# MacBook Bridge/T2 Linux Driver
A driver for MacBook models 2018 and newer, implementing the VHCI (required for mouse/keyboard/etc.) and audio functionality.

The project is divided into 3 main components:
- BCE (Buffer Copy Engine) - this is what the files in the root directory are for. This estabilishes a basic communication channel with the T2. VHCI and Audio both require this component.
- VHCI - this is a virtual USB host controller; keyboard, mouse and other system components are provided by this component (other drivers use this host controller to provide more functionality, however USB drivers are not in this project's scope).
- Audio - a driver for the T2 audio interface, currently only audio output is supported.

## Suspend/Resume

System suspend and resume (S3) is supported. The driver performs cold re-enumeration of all USB devices on wake, matching the macOS x86 protocol.

### Touch Bar (tiny-dfr) after resume

The Touch Bar display (DFR) is handled by the `appletbdrm` driver and the `tiny-dfr` userspace service. After resume, `tiny-dfr` needs to be restarted because systemd kills it during suspend. To handle this automatically the udev rule can be installed:

```sh
sudo cp 99-tiny-dfr-restart.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

If you want to support me, you can do so by donating to me on PayPal: https://paypal.me/mcmrarm
