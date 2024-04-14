#pragma once
#include <winioctl.h>
#define  SYMBOLIC_NAME "\\\\.\\sym_name"
#define NETSYM_NAME "\\\\.\\sknetflt"
#define _USB_SYS_NAME "\\\\.\\usbsysmblicname"
#define WPDSYM_NAME "\\\\.\\wpdflt"
#define MOUSYM_NAME "\\\\.\\mouflt"
#define CTL_CODE_BASE 0x8000
#define CTL_CMD(i) CTL_CODE(FILE_DEVICE_UNKNOWN,CTL_CODE_BASE+i,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define  CTL_PROT CTL_CMD(1)
#define  CTL_KILL CTL_CMD(2)
#define  CTL_UNPROT CTL_CMD(3)
#define  CTL_ADDDLL CTL_CMD(4)
#define  CTL_DELDLL CTL_CMD(5)
#define  CTL_DELFILE CTL_CMD(6)
#define  CTL_PROTECT_FILE CTL_CMD(7)
#define  CTL_DISABLE_DEBUG CTL_CMD(8)
#define  CTL_ENABLE_DEBUG CTL_CMD(9)
#define  CTL_ADDFILE CTL_CMD(10)
#define  CTL_DELFILENAME CTL_CMD(11)
#define  CTL_BLOCK CTL_CMD(12)
#define  CTL_REMOVEBLOCK CTL_CMD(13)
#define  CTL_BLOCKUSB CTL_CMD(14)
#define  CTL_ALLOWUSB CTL_CMD(15)
#define  CTL_START_WPDFLT CTL_CMD(66)
#define  CTL_STOP_WPDFLT CTL_CMD(67)
#define  CTL_START_MOUFLT CTL_CMD(68)
#define  CTL_STOP_MOUFLT CTL_CMD(69)



