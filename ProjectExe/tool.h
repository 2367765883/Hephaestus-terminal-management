#pragma once
#include "headers.h"
#define MEM_TAG 0x100
#define MEM_TAG2 0x101
#define FILE_NUM 50
#define PROCESS_NUM 10
#define IP_NUM 20
#define PROCESS_TERMINATE 0x0001
#define PROCESS_SUSPEND_RESUME 0x0800
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef struct _IMG_DATA
{
	HANDLE ProcessId;
	PVOID pImageBase;
}IMG_DATA, * PIMG_DATA;




// 声明微软未公开的ObReferenceObjectByName()函数
NTSTATUS ObReferenceObjectByName(
	PUNICODE_STRING ObjectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContest,
	PVOID* Object
);

extern POBJECT_TYPE* IoDriverObjectType;

extern RTL_OSVERSIONINFOW osinfo;

extern PDRIVER_OBJECT g_PDriver;

extern UNICODE_STRING g_FltRegPath;



//0x78 bytes (sizeof)
typedef struct _OBJECT_TYPE_INITIALIZER
{
	USHORT Length;                                                          //0x0
	union
	{
		USHORT ObjectTypeFlags;                                             //0x2
		struct
		{
			UCHAR CaseInsensitive : 1;                                        //0x2
			UCHAR UnnamedObjectsOnly : 1;                                     //0x2
			UCHAR UseDefaultObject : 1;                                       //0x2
			UCHAR SecurityRequired : 1;                                       //0x2
			UCHAR MaintainHandleCount : 1;                                    //0x2
			UCHAR MaintainTypeList : 1;                                       //0x2
			UCHAR SupportsObjectCallbacks : 1;                                //0x2
			UCHAR CacheAligned : 1;                                           //0x2
			UCHAR UseExtendedParameters : 1;                                  //0x3
			UCHAR Reserved : 7;                                               //0x3
		};
	};
	ULONG ObjectTypeCode;                                                   //0x4
	ULONG InvalidAttributes;                                                //0x8
	struct _GENERIC_MAPPING GenericMapping;                                 //0xc
	ULONG ValidAccessMask;                                                  //0x1c
	ULONG RetainAccess;                                                     //0x20
	enum _POOL_TYPE PoolType;                                               //0x24
	ULONG DefaultPagedPoolCharge;                                           //0x28
	ULONG DefaultNonPagedPoolCharge;                                        //0x2c
	VOID(*DumpProcedure)(VOID* arg1, struct _OBJECT_DUMP_CONTROL* arg2);   //0x30
	LONG(*OpenProcedure)(enum _OB_OPEN_REASON arg1, CHAR arg2, struct _EPROCESS* arg3, VOID* arg4, ULONG* arg5, ULONG arg6); //0x38
	VOID(*CloseProcedure)(struct _EPROCESS* arg1, VOID* arg2, ULONGLONG arg3, ULONGLONG arg4); //0x40
	VOID(*DeleteProcedure)(VOID* arg1);                                    //0x48
	union
	{
		LONG(*ParseProcedure)(VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8, struct _SECURITY_QUALITY_OF_SERVICE* arg9, VOID** arg10); //0x50
		LONG(*ParseProcedureEx)(VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8, struct _SECURITY_QUALITY_OF_SERVICE* arg9, struct _OB_EXTENDED_PARSE_PARAMETERS* arg10, VOID** arg11); //0x50
	};
	LONG(*SecurityProcedure)(VOID* arg1, enum _SECURITY_OPERATION_CODE arg2, ULONG* arg3, VOID* arg4, ULONG* arg5, VOID** arg6, enum _POOL_TYPE arg7, struct _GENERIC_MAPPING* arg8, CHAR arg9); //0x58
	LONG(*QueryNameProcedure)(VOID* arg1, UCHAR arg2, struct _OBJECT_NAME_INFORMATION* arg3, ULONG arg4, ULONG* arg5, CHAR arg6); //0x60
	UCHAR(*OkayToCloseProcedure)(struct _EPROCESS* arg1, VOID* arg2, VOID* arg3, CHAR arg4); //0x68
	ULONG WaitObjectFlagMask;                                               //0x70
	USHORT WaitObjectFlagOffset;                                            //0x74
	USHORT WaitObjectPointerOffset;                                         //0x76
}OBJECT_TYPE_INITIALIZER,*POBJECT_TYPE_INITIALIZER;



//0xd8 bytes (sizeof)
typedef struct _OBJECT_TYPE
{
	struct _LIST_ENTRY TypeList;                                            //0x0
	struct _UNICODE_STRING Name;                                            //0x10
	VOID* DefaultObject;                                                    //0x20
	UCHAR Index;                                                            //0x28
	ULONG TotalNumberOfObjects;                                             //0x2c
	ULONG TotalNumberOfHandles;                                             //0x30
	ULONG HighWaterNumberOfObjects;                                         //0x34
	ULONG HighWaterNumberOfHandles;                                         //0x38
	OBJECT_TYPE_INITIALIZER TypeInfo;                                       //0x40
                                  
}OBJECT_TYPE,*POBJECT_TYPE;



typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;



typedef struct _MY_OBJECT_TYPE                   // 12 elements, 0xD0 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY TypeList;              // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _UNICODE_STRING Name;              // 3 elements, 0x10 bytes (sizeof)
	/*0x020*/     VOID* DefaultObject;
	/*0x028*/     UINT8        Index;
	/*0x029*/     UINT8        _PADDING0_[0x3];
	/*0x02C*/     ULONG32      TotalNumberOfObjects;
	/*0x030*/     ULONG32      TotalNumberOfHandles;
	/*0x034*/     ULONG32      HighWaterNumberOfObjects;
	/*0x038*/     ULONG32      HighWaterNumberOfHandles;
	/*0x03C*/     UINT8        _PADDING1_[0x4];
	/*0x040*/     OBJECT_TYPE_INITIALIZER TypeInfo; // 25 elements, 0x70 bytes (sizeof)

}MY_OBJECT_TYPE, * PMY_OBJECT_TYPE;






typedef struct _CALLBACK_ENTRY
{
	LIST_ENTRY CallbackList;
	OB_OPERATION  Operations;
	ULONG Active;
	PVOID Handle;
	POBJECT_TYPE ObjectType;
	POB_PRE_OPERATION_CALLBACK  PreOperation;
	POB_POST_OPERATION_CALLBACK PostOperation;
	ULONG unknown;
} CALLBACK_ENTRY, * PCALLBACK_ENTRY;

typedef struct _LDR_DATA                         // 24 elements, 0xE0 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
	/*0x030*/     VOID* DllBase;
	/*0x038*/     VOID* EntryPoint;
	/*0x040*/     ULONG32      SizeOfImage;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
	/*0x058*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
	/*0x068*/     ULONG32      Flags;
	/*0x06C*/     UINT16       LoadCount;
	/*0x06E*/     UINT16       TlsIndex;
	union                                                    // 2 elements, 0x10 bytes (sizeof)
	{
		/*0x070*/         struct _LIST_ENTRY HashLinks;                        // 2 elements, 0x10 bytes (sizeof)
		struct                                               // 2 elements, 0x10 bytes (sizeof)
		{
			/*0x070*/             VOID* SectionPointer;
			/*0x078*/             ULONG32      CheckSum;
			/*0x07C*/             UINT8        _PADDING1_[0x4];
		};
	};
	union                                                    // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x080*/         ULONG32      TimeDateStamp;
		/*0x080*/         VOID* LoadedImports;
	};
	/*0x088*/     struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	/*0x090*/     VOID* PatchInformation;
	/*0x098*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x10 bytes (sizeof)
	/*0x0A8*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x10 bytes (sizeof)
	/*0x0B8*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x10 bytes (sizeof)
	/*0x0C8*/     VOID* ContextInformation;
	/*0x0D0*/     UINT64       OriginalBase;
	/*0x0D8*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)
}LDR_DATA, * PLDR_DATA;






NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);
EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationProcess(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
);

typedef NTSTATUS(*MyNtOpenProcess)(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);


typedef NTSTATUS(*ZWDELETEFILE)(
	IN POBJECT_ATTRIBUTES ObjectAttributes
	);

EXTERN_C CHAR* IPs[IP_NUM];
EXTERN_C  HANDLE PidArray[10];
EXTERN_C CHAR *DllArray[DLL_NUM];
EXTERN_C UNICODE_STRING unImgFileName;
EXTERN_C UNICODE_STRING unBlackProcessName[FILE_NUM];
PDEVICE_OBJECT g_KeyboardDeviceObject = NULL;
PDEVICE_OBJECT g_MouseDeviceObject = NULL;
PVOID ADDR = (PVOID)0;
MyNtOpenProcess NtOpen = NULL;
PVOID pDbgkDebugObjectTypeAddr = NULL;
ULONG64 uOrgValidAccessMask;

EXTERN_C UNICODE_STRING unFileNames[FILE_NUM];



EXTERN_C NTSTATUS KeyboardCallback(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);
EXTERN_C NTSTATUS MouseCallback(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);
EXTERN_C NTSTATUS DisableKeyboardAndMouse();
EXTERN_C VOID EnableKeyboardAndMouse();
EXTERN_C  PVOID SearchSpecialCode(PVOID pSearchBeginAddr, ULONG ulSearchLength, PUCHAR pSpecialCode, ULONG ulSpecialCodeLength);
EXTERN_C  ULONG_PTR GetKernelModuleBase(PUCHAR moduleName, PULONG pModuleSize);
EXTERN_C  PVOID GetNtFuncAddr(unsigned char* NtFuncShellCode, ULONG uFuncCodeLen);
//offset  -0x3c
EXTERN_C PVOID GetDebugTypeAddr();
EXTERN_C NTSTATUS DispatchCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
EXTERN_C VOID InitDriver(PDRIVER_OBJECT pDriver);
EXTERN_C NTSTATUS DispatchControl(PDEVICE_OBJECT pDevice, PIRP pIrp);
EXTERN_C DWORD HandleToPid(IN HANDLE hProcess);
EXTERN_C BOOLEAN KillProcess(ULONG PID);
EXTERN_C NTSTATUS DeleFile(UNICODE_STRING targetFile);
EXTERN_C VOID ProtectFile(const char* filePath);
EXTERN_C VOID DisableDebugThread();
EXTERN_C VOID EnbleDebugThread();
EXTERN_C VOID ThreadProc(_In_ PVOID StartContext);
EXTERN_C VOID RegistCallBack();
EXTERN_C VOID RegFileCallBack();
EXTERN_C NTSTATUS DenyLoadDll(HANDLE ProcessId, PVOID pImageBase);
EXTERN_C NTSTATUS MmUnmapViewOfSection(PEPROCESS Process, PVOID BaseAddress);
EXTERN_C OB_PREOP_CALLBACK_STATUS FileCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
EXTERN_C VOID EnableObType(POBJECT_TYPE ObjectType);
EXTERN_C VOID InitFileFilter(PDRIVER_OBJECT pDriver);
EXTERN_C VOID UnloadFileFilter();
EXTERN_C VOID CreateProcessCallBack(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);
EXTERN_C VOID LoadImageCallBack(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo
);
EXTERN_C UNICODE_STRING ConvertToUnicodeString(char* asciiString);
EXTERN_C NTSTATUS Unicode2Char(PUNICODE_STRING unicode, PCHAR pChar, ULONG uLenth);




typedef struct _Dev_exten
{
	ULONG Size;						// 该结构大小
	PDEVICE_OBJECT FilterDevice;	// 过滤设备对象
	PDEVICE_OBJECT TargeDevice;		// 下一设备对象
	PDEVICE_OBJECT LowDevice;		// 最底层设备对象
	KSPIN_LOCK IoRequestSpinLock;	// 自旋锁
	KEVENT IoInProgressEvent;		// 事件
	PIRP pIrp;						// IRP
} DEV_EXTENSION, * PDEV_EXTENSION;


NTSTATUS GetWindowsVersion(OUT PRTL_OSVERSIONINFOW pOsVersionInfo);
NTSTATUS DeAttach(PDEVICE_OBJECT pdevice);
NTSTATUS unloadWpdFlt(PDRIVER_OBJECT pDriver);
NTSTATUS GeneralDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS PowerDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS PnPDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS DevExtInit(PDEV_EXTENSION devExt, PDEVICE_OBJECT filterDevice, PDEVICE_OBJECT targetDevice, PDEVICE_OBJECT lowDevice);
NTSTATUS AttachDevice(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPatch);
NTSTATUS StartFltWpd(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPath);