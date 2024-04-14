#pragma once

#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <ntddkbd.h>
#include <ntddmou.h>
#include <wdm.h>
#include <ntstatus.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <intsafe.h>
#include <stdlib.h>



#define DLL_NUM 20
#define DLL_CHAR 126
#define  DEVICE_NAME L"\\device\\mydevice"
#define  SYMBOLIC_NAME L"\\dosdevices\\sym_name"
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
#define  CTL_BLOCK_IP CTL_CMD(12)
#define  CTL_BLOCKUSB CTL_CMD(14)
#define  CTL_ALLOWUSB CTL_CMD(15)