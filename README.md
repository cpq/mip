# TCP/IP stack for microcontrollers

- BSD socket API, non-blocking mode only
- Built-in drivers for STM32, NXP, TI TM4C, W5500

## Integration guide

- Clone, copy, or submodule this repo into your source tree
- Add `mip/mip.c` and `mip/drivers/driver_xxxx.c` to your sources
- Add `mip/` to your include path

Example Makefile snippet:

```make
mip mip/mip.c:
	git clone --depth 1 -b main https://github.com/cpq/mip $@

SOURCES += mip/mip.c mip/drivers/driver_stm32.c
CFLAGS  += -Imip -Dmip_random=mg_random -Dmip_millis=mg_millis
```
