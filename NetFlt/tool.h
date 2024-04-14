#pragma once

#define NDIS_SUPPORT_NDIS6 1
#define IPS_NUM	20
#define DEV_NAME L"\\Device\\sknetflt"
#define NETSYM_NAME L"\\DosDevices\\sknetflt"
#define CTL_CODE_BASE 0x8000
#define CTL_CMD(i) CTL_CODE(FILE_DEVICE_UNKNOWN,CTL_CODE_BASE+i,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define  CTL_BLOCK CTL_CMD(12)
#define  CTL_REMOVEBLOCK CTL_CMD(13)


#include <ntifs.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h >
#include <stdio.h>


extern UNICODE_STRING unicodeString;

// 过滤器引擎句柄
extern HANDLE g_hEngine;

// 过滤器引擎中的callout的运行时标识符
extern ULONG32 g_AleConnectCalloutId;

// 过滤器的运行时标识符
extern ULONG64 g_AleConnectFilterId;

// 指定唯一UUID值(只要不冲突即可,内容可随意)
extern GUID GUID_ALE_AUTH_CONNECT_CALLOUT_V4 ;

extern CHAR g_IPBlackList[IPS_NUM][IPS_NUM];

extern KSPIN_LOCK IpListSpinLock;

// 注册Callout并设置过滤点
NTSTATUS RegisterCalloutForLayer(
	IN PDEVICE_OBJECT pDevObj,
	IN const GUID* layerKey,
	IN const GUID* calloutKey,
	IN FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	IN FWPS_CALLOUT_NOTIFY_FN notifyFn,
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn,
	OUT ULONG32* calloutId,
	OUT ULONG64* filterId,
	OUT HANDLE* engine);

// 注册Callout
NTSTATUS RegisterCallout(
	PDEVICE_OBJECT pDevObj,
	IN const GUID* calloutKey,
	IN FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	IN FWPS_CALLOUT_NOTIFY_FN notifyFn,
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn,
	OUT ULONG32* calloutId);

// 设置过滤点
NTSTATUS SetFilter(
	IN const GUID* layerKey,
	IN const GUID* calloutKey,
	OUT ULONG64* filterId,
	OUT HANDLE* engine);

// Callout函数 flowDeleteFn
VOID NTAPI flowDeleteFn(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext
);

// Callout函数 classifyFn
#if (NTDDI_VERSION >= NTDDI_WIN8)
VOID NTAPI classifyFn(
	_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER2* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);
#elif (NTDDI_VERSION >= NTDDI_WIN7)                       
VOID NTAPI classifyFn(
	_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER1* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);
#else
VOID NTAPI classifyFn(
	_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);
#endif

// Callout函数 notifyFn
#if (NTDDI_VERSION >= NTDDI_WIN8)
NTSTATUS NTAPI notifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER2* filter
);
#elif (NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS NTAPI notifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER1* filter
);
#else
NTSTATUS NTAPI notifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER0* filter
);
#endif


NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject);
NTSTATUS DispatchControl(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS ProtocalIdToName(UINT16 protocalId, PCHAR lpszProtocalName);
NTSTATUS WfpLoad(PDEVICE_OBJECT pDevObj);
NTSTATUS WfpUnload();

NTSTATUS RegisterCalloutForLayer(IN PDEVICE_OBJECT pDevObj, IN const GUID* layerKey, IN const GUID* calloutKey, IN FWPS_CALLOUT_CLASSIFY_FN classifyFn, IN FWPS_CALLOUT_NOTIFY_FN notifyFn, IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn, OUT ULONG32* calloutId, OUT ULONG64* filterId, OUT HANDLE* engine);
NTSTATUS RegisterCallout(PDEVICE_OBJECT pDevObj, IN const GUID* calloutKey, IN FWPS_CALLOUT_CLASSIFY_FN classifyFn, IN FWPS_CALLOUT_NOTIFY_FN notifyFn, IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn, OUT ULONG32* calloutId);


// Callout函数 classifyFn 事前回调函数
VOID NTAPI classifyFn(
	_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER2* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT0* classifyOut);


NTSTATUS NTAPI notifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER2* filter);

// Callout函数 flowDeleteFn 事后回调函数
VOID NTAPI flowDeleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId, _In_ UINT64 flowContext);

VOID UnDriver(PDRIVER_OBJECT driver);

