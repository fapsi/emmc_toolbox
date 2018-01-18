/*
 * shellcode.h
 * Copyright (C) 2017 Oran Avraham (contact@oranav.me): Original Implementation
 * Copyright (C) 2018 Fapsi: Added n7100-XXDME6
 *
 * Distributed under terms of the GPLv3 license.
 */

#ifndef _SHELLCODE_H_
#define _SHELLCODE_H_

/* Structs and typedefs */
struct mmc_cmd {
	unsigned short cmdidx;
	unsigned int resp_type;
	unsigned int cmdarg;
	unsigned int response[4];
	unsigned int flags;
};

struct mmc_data {
	union {
		char *dest;
		const char *src;
	};
	unsigned flags;
	unsigned blocks;
	unsigned blocksize;
};

#define MMC_DEV_SIZE 200
#define MMC_HOST_SIZE 56

#define SBOOT_VERSION 1 /* possible values 
[(i9300,XXELLA,sha256=47e0950cfac2e29556dfe6a6ce04d34731bcfb642ce9bc331aa99ddfa01aa694 ) = 0,
 (n7100,XXDME6,sha256=0bd4729f53c4719109a35a2ad9ab310b3b8c0ce146cfaa39176fbcf0c9f542ab ) = 1] */

#if SBOOT_VERSION == 0

/* Constants from actual firmware - sboot version XXELLA */
typedef int _memset(void *, unsigned char, unsigned);
#define memset ((_memset*)0x43E02450)

typedef int _before();
#define before ((_before*)0x43E0B8E0)

typedef void _display(int, int, int, int, const char *, ...);
#define display ((_display*)0x43E14B38)

typedef int _reboot();
#define reboot ((_reboot*)0x43E060B0)

typedef void _sleep(int);
#define sleep ((_sleep*)0x43E046E8)

typedef void _usb_write(const void *, unsigned);
#define usb_write ((_usb_write*)0x43E24C2C)

typedef void _usb_read(void *, unsigned);
#define usb_read ((_usb_read*)0x43E24C64)

typedef void _s5c_mshc_init(void *);
#define s5c_mshc_init ((_s5c_mshc_init*)0x43E1E718)

typedef void _emmc_poweroff();
#define emmc_poweroff ((_emmc_poweroff*)0x43E1BD70)

typedef void _emmc_poweron();
#define emmc_poweron ((_emmc_poweron*)0x43E1BBC8)

typedef void _clk1(void *, int);
#define clk1 ((_clk1*)0x43E1ABEC)

typedef void _clk2(void* ,int);
#define clk2 ((_clk2*)0x43E1AC6C)

typedef int _mmc_startup(void *);
#define mmc_startup ((_mmc_startup*)0x43E1B75C)

typedef int _mmc_send_op_cond(void*);
#define mmc_send_op_cond ((_mmc_send_op_cond*)0x43E18AA0)

typedef void _call_init_functions();
#define call_init_functions ((_call_init_functions*)0x43E016D8)

typedef int _mmc_initialize();
#define mmc_initialize ((_mmc_initialize*)0x43E1BBE8)

typedef int _boot();
#define boot ((_boot*)0x43E016A4)

typedef void _restart_handler();
#define restart_handler ((_restart_handler*)0x43E00020)

typedef void _setenv(unsigned cmd, unsigned val_int, const char *val_str,
		int commit);
#define setenv ((_setenv*)0x43E0AA9C)

typedef void _saveenv();
#define saveenv ((_saveenv*)0x43E0A8FC)

#define mmc_host (void*)0x43EF5790
#define mmc_dev (void*)0x43EF4840

#elif SBOOT_VERSION == 1

/* Constants from actual firmware - sboot version XXDME6 */
typedef int _memset(void *, unsigned char, unsigned);
#define memset ((_memset*)0x43E02640) /* VERIFIED */

typedef int _before();
#define before ((_before*)0x43E0BBE0) /* SEMI-VERIFIED: (function-flow change) */

typedef void _display(int, int, int, int, const char *, ...);
#define display ((_display*)0x43E14E4C) /* VERIFIED */

typedef int _reboot();
#define reboot ((_reboot*)0x43E063A4) /* VERIFIED (in procedure) */

typedef void _sleep(int);
#define sleep ((_sleep*)0x43E049DC) /* VERIFIED */

typedef void _usb_write(const void *, unsigned); /* VERIFIED */
#define usb_write ((_usb_write*)0x43E2610C)

typedef void _usb_read(void *, unsigned);
#define usb_read ((_usb_read*)0x43E26144) /* VERIFIED */

typedef void _s5c_mshc_init(void *);
#define s5c_mshc_init ((_s5c_mshc_init*)0x43E1FB14) /* VERIFIED */

typedef void _emmc_poweroff();
#define emmc_poweroff ((_emmc_poweroff*)0x43E1D2E8) /* VERIFIED */

typedef void _emmc_poweron();
#define emmc_poweron ((_emmc_poweron*)0x43E1D150) /* VERIFIED */

typedef void _clk1(void *, int);
#define clk1 ((_clk1*)0x43E1C1AC) /* VERIFIED */

typedef void _clk2(void* ,int);
#define clk2 ((_clk2*)0x43E1C224) /* VERIFIED */

typedef int _mmc_startup(void *);
#define mmc_startup ((_mmc_startup*)0x43E1C254) /* SEMI-VERIFIED (change in parameter/function) */

typedef int _mmc_send_op_cond(void*);
#define mmc_send_op_cond ((_mmc_send_op_cond*)0x43E1931C) /* SEMI-VERIFIED (change in parameter/function) */

typedef void _call_init_functions();
#define call_init_functions ((_call_init_functions*)0x43E018C8) /* VERIFIED */

/* Noticed to late, that this ones are unused. */

typedef int _mmc_initialize();
#define mmc_initialize ((_mmc_initialize*)0x43E1D170) /* VERIFIED (unused) */

typedef int _boot();
#define boot ((_boot*)0x43E01894) /* VERIFIED (unused) */

typedef void _restart_handler();
#define restart_handler ((_restart_handler*)0x43E00020) /* UNCHANGED (ununsed) */

typedef void _setenv(unsigned cmd, unsigned val_int, const char *val_str,
		int commit);
#define setenv ((_setenv*)0x43E0AD9C) /* VERIFIED (unused) */

typedef void _saveenv();
#define saveenv ((_saveenv*)0x43E0ABFC) /* VERIFIED (unused) */

/* 
 These ones are necessary and were tricky.
 0) Get S-Boot from device with data behind. 
 1) Used emmc_poweron() for rough determination off offset to XXELLA (search for 43efd register writes)
 2) Then look out for a struct (mmc_dev) containing a string-variable with value "S5P_MSHC4" (maybe directly search for it). 
 3) mmc_host is the only data left behind the previous struct.
*/

#define mmc_host (void*)0x43EE968C /* VERIFIED  0x43EE5818 */
#define mmc_dev (void*)0x43EE8870 /* VERIFIED */

#else 

#endif

#endif
