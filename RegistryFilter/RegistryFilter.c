/*++

Module Name:

    RegistryFilter.c

Abstract:

    This is the main module of the RegistryFilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <ntifs.h>
#include <windef.h>
#include "util.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

struct {
	PDRIVER_OBJECT DriverObject;
	PFLT_FILTER Filter;
	PFLT_PORT ServerPort;
	PEPROCESS UserProcess;
	ULONG PID;
	PFLT_PORT ClientPort;
} gMessage;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
RegistryFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
RegistryFilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
RegistryFilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
RegistryFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
RegistryFilterInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
RegistryFilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID
RegistryFilterOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
RegistryFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
RegistryFilterPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

BOOLEAN
RegistryFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, RegistryFilterUnload)
#pragma alloc_text(PAGE, RegistryFilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, RegistryFilterInstanceSetup)
#pragma alloc_text(PAGE, RegistryFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, RegistryFilterInstanceTeardownComplete)
#endif


// 未导出函数声明 pEProcess -> PID
PUCHAR PsGetProcessImageFileName(PEPROCESS pEProcess);
// 注册表回调Cookie
LARGE_INTEGER g_liRegCookie;

NTSTATUS ObQueryNameString(
    _In_ PVOID Object,
    _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength
);


//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_CLOSE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_READ,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_WRITE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_SET_EA,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      RegistryFilterPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_PNP,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      RegistryFilterPreOperation,
      RegistryFilterPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    RegistryFilterUnload,                           //  MiniFilterUnload

    RegistryFilterInstanceSetup,                    //  InstanceSetup
    RegistryFilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    RegistryFilterInstanceTeardownStart,            //  InstanceTeardownStart
    RegistryFilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
RegistryFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("RegistryFilter!RegistryFilterInstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}


NTSTATUS
RegistryFilterInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("RegistryFilter!RegistryFilterInstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}


VOID
RegistryFilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("RegistryFilter!RegistryFilterInstanceTeardownStart: Entered\n"));
}


VOID
RegistryFilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("RegistryFilter!RegistryFilterInstanceTeardownComplete: Entered\n"));
}


NTSTATUS
MessagePortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID* ConnectionCookie
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	ASSERT(gMessage.ClientPort == NULL);
	ASSERT(gMessage.UserProcess == NULL);

	gMessage.UserProcess = PsGetCurrentProcess();
	gMessage.PID = (ULONG)PsGetCurrentProcessId();
	gMessage.ClientPort = ClientPort;

	DbgPrint("!!! FsMiniFilter -- connected, port=0x%p, pid=%d\n", ClientPort, gMessage.PID);


	return STATUS_SUCCESS;
}



VOID MessagePortDisconnect(
	__in_opt PVOID ConnectionCookie
)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);


	PAGED_CODE();


	DbgPrint("!!! FsMiniFilter -- disconnected, port=0x%p\n", gMessage.ClientPort);

	FltCloseClientPort(gMessage.Filter, &gMessage.ClientPort);
	gMessage.UserProcess = NULL;
	gMessage.PID = 0;
}


// 获取注册表完整路径
BOOLEAN GetFullPath(PUNICODE_STRING pRegistryPath, PVOID pRegistryObject)
{
    // 判断数据地址是否有效
    if ((FALSE == MmIsAddressValid(pRegistryObject)) ||
        (NULL == pRegistryObject))
    {
        return FALSE;
    }
    // 申请内存
    ULONG ulSize = 512;
    PVOID lpObjectNameInfo = ExAllocatePool(NonPagedPool, ulSize);
    if (NULL == lpObjectNameInfo)
    {
        return FALSE;
    }
    // 获取注册表路径
    ULONG ulRetLen = 0;
    NTSTATUS status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)lpObjectNameInfo, ulSize, &ulRetLen);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(lpObjectNameInfo);
        return FALSE;
    }
    // 复制
    RtlCopyUnicodeString(pRegistryPath, (PUNICODE_STRING)lpObjectNameInfo);
    // 释放内存
    ExFreePool(lpObjectNameInfo);
    return TRUE;
}

// 注册表回调函数
NTSTATUS RegCallback(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING ustrRegPath;

    // 获取操作类型
    LONG lOperateType = (REG_NOTIFY_CLASS)Argument1;

    // 申请内存
    ustrRegPath.Length = 0;
    ustrRegPath.MaximumLength = 1024 * sizeof(WCHAR);
    ustrRegPath.Buffer = ExAllocatePool(NonPagedPool, ustrRegPath.MaximumLength);
    if (NULL == ustrRegPath.Buffer)
    {
        return status;
    }
    RtlZeroMemory(ustrRegPath.Buffer, ustrRegPath.MaximumLength);

    // 判断操作
    switch (lOperateType)
    {
        // 创建注册表之前
    case RegNtPreCreateKey:
    {
       
        GetFullPath(&ustrRegPath, ((PREG_CREATE_KEY_INFORMATION)Argument2)->RootObject);

        PMESSAGE_REQ reqBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REQ), 'UGET');
        PMESSAGE_REPLY replyBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER), 'UGET');

        RtlZeroMemory(reqBuffer, sizeof(MESSAGE_REQ));
        RtlZeroMemory(replyBuffer, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER));

        RtlCopyMemory(reqBuffer->Regpath, ustrRegPath.Buffer, wcslen(ustrRegPath.Buffer) * 2);
        reqBuffer->uPid = PsGetCurrentProcessId();

        ULONG reqLength = sizeof(MESSAGE_REQ);
        ULONG replyLength = sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER);
        status = FltSendMessage(gMessage.Filter, &gMessage.ClientPort, reqBuffer
            , reqLength, replyBuffer, &replyLength, NULL);

        if (NT_SUCCESS(status))
        {
            DbgPrint("[reg]okkkkk\n");
        }

        ExFreePoolWithTag(reqBuffer, 'UGET');
        ExFreePoolWithTag(replyBuffer, 'UGET');

        if (replyBuffer->IsSafe == 99)
        {
            return STATUS_SUCCESS;
        }

        

        break;
    }
    // 打开注册表之前
    case RegNtPreOpenKey:
    {
        
        //// 获取注册表路径
        //GetFullPath(&ustrRegPath, ((PREG_CREATE_KEY_INFORMATION)Argument2)->RootObject);
    
        //PMESSAGE_REQ reqBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REQ), 'UGET');
        //PMESSAGE_REPLY replyBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER), 'UGET');

        //RtlZeroMemory(reqBuffer, sizeof(MESSAGE_REQ));
        //RtlZeroMemory(replyBuffer, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER));

        //RtlCopyMemory(reqBuffer->Regpath, ustrRegPath.Buffer, wcslen(ustrRegPath.Buffer) * 2);
        //reqBuffer->uPid = PsGetCurrentProcessId();

        //ULONG reqLength = sizeof(MESSAGE_REQ);
        //ULONG replyLength = sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER);
        //status = FltSendMessage(gMessage.Filter, &gMessage.ClientPort, reqBuffer
        //    , reqLength, replyBuffer, &replyLength, NULL);

        //if (NT_SUCCESS(status))
        //{
        //    DbgPrint("[reg]okkkkk\n");
        //}

        //ExFreePoolWithTag(reqBuffer, 'UGET');
        //ExFreePoolWithTag(replyBuffer, 'UGET');

        //if (replyBuffer->IsSafe == 99)
        //{
        //    return STATUS_SUCCESS;
        //}

      
       
        break;
    }
    // 删除键之前
    case RegNtPreDeleteKey:
    {
        //// 获取注册表路径
        //GetFullPath(&ustrRegPath, ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object);
        //
        //PMESSAGE_REQ reqBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REQ), 'UGET');
        //PMESSAGE_REPLY replyBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER), 'UGET');

        //RtlZeroMemory(reqBuffer, sizeof(MESSAGE_REQ));
        //RtlZeroMemory(replyBuffer, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER));

        //RtlCopyMemory(reqBuffer->Regpath, ustrRegPath.Buffer, wcslen(ustrRegPath.Buffer) * 2);
        //reqBuffer->uPid = PsGetCurrentProcessId();

        //ULONG reqLength = sizeof(MESSAGE_REQ);
        //ULONG replyLength = sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER);
        //status = FltSendMessage(gMessage.Filter, &gMessage.ClientPort, reqBuffer
        //    , reqLength, replyBuffer, &replyLength, NULL);

        //if (NT_SUCCESS(status))
        //{
        //    DbgPrint("[reg]okkkkk\n");
        //}

        //ExFreePoolWithTag(reqBuffer, 'UGET');
        //ExFreePoolWithTag(replyBuffer, 'UGET');

        //if (replyBuffer->IsSafe == 99)
        //{
        //    
        //    return STATUS_SUCCESS;
        //}


        break;
    }
    // 删除键值之前
    case RegNtPreDeleteValueKey:
    {
        //// 获取注册表路径
        //GetFullPath(&ustrRegPath, ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->Object);
        //
        //PMESSAGE_REQ reqBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REQ), 'UGET');
        //PMESSAGE_REPLY replyBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER), 'UGET');

        //RtlZeroMemory(reqBuffer, sizeof(MESSAGE_REQ));
        //RtlZeroMemory(replyBuffer, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER));

        //RtlCopyMemory(reqBuffer->Regpath, ustrRegPath.Buffer, wcslen(ustrRegPath.Buffer) * 2);
        //reqBuffer->uPid = PsGetCurrentProcessId();

        //ULONG reqLength = sizeof(MESSAGE_REQ);
        //ULONG replyLength = sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER);
        //status = FltSendMessage(gMessage.Filter, &gMessage.ClientPort, reqBuffer
        //    , reqLength, replyBuffer, &replyLength, NULL);

        //if (NT_SUCCESS(status))
        //{
        //    DbgPrint("[reg]okkkkk\n");
        //}

        //ExFreePoolWithTag(reqBuffer, 'UGET');
        //ExFreePoolWithTag(replyBuffer, 'UGET');

        //if (replyBuffer->IsSafe == 99)
        //{
        //    return STATUS_SUCCESS;
        //}

       

        break;
    }
    // 修改键值之前
    case RegNtPreSetValueKey:
    {

        //// 获取注册表路径
        //GetFullPath(&ustrRegPath, ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object);
        //
        //PMESSAGE_REQ reqBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REQ), 'UGET');
        //PMESSAGE_REPLY replyBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER), 'UGET');

        //RtlZeroMemory(reqBuffer, sizeof(MESSAGE_REQ));
        //RtlZeroMemory(replyBuffer, sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER));

        //RtlCopyMemory(reqBuffer->Regpath, ustrRegPath.Buffer, wcslen(ustrRegPath.Buffer) * 2);
        //reqBuffer->uPid = PsGetCurrentProcessId();

        //ULONG reqLength = sizeof(MESSAGE_REQ);
        //ULONG replyLength = sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER);
        //status = FltSendMessage(gMessage.Filter, &gMessage.ClientPort, reqBuffer
        //    , reqLength, replyBuffer, &replyLength, NULL);

        //if (NT_SUCCESS(status))
        //{
        //    DbgPrint("[reg]okkkkk\n");
        //}

        //ExFreePoolWithTag(reqBuffer, 'UGET');
        //ExFreePoolWithTag(replyBuffer, 'UGET');

        //if (replyBuffer->IsSafe == 99)
        //{
        //    return STATUS_SUCCESS;
        //}

      

        break;
    }
    default:
        break;
    }

    // 释放内存
    if (NULL != ustrRegPath.Buffer)
    {
        ExFreePool(ustrRegPath.Buffer);
        ustrRegPath.Buffer = NULL;
    }

    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    CmRegisterCallback(RegCallback, NULL, &g_liRegCookie);

	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsMiniFilter!DriverEntry: Entered\n"));

	//
	//  Register with FltMgr to tell it our callback routines
	//

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterHandle);
	gMessage.Filter = gFilterHandle;

	if (!NT_SUCCESS(status))
		return status;

	RtlInitUnicodeString(&uniString, MESSAGE_PORT_NAME);
	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	if (NT_SUCCESS(status)) {
		InitializeObjectAttributes(&oa, &uniString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
		status = FltCreateCommunicationPort(gMessage.Filter, &gMessage.ServerPort, &oa, NULL,
			MessagePortConnect, MessagePortDisconnect, NULL, 1);
		FltFreeSecurityDescriptor(sd);

		if (NT_SUCCESS(status)) {
			status = FltStartFiltering(gFilterHandle);
			if (NT_SUCCESS(status))
				return status;
			else FltCloseCommunicationPort(gMessage.ServerPort);
		}
	}
	FltUnregisterFilter(gFilterHandle);
	return status;
}

NTSTATUS
RegistryFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER(Flags);

    //PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("RegistryFilter!RegistryFilterUnload: Entered\n"));

    // 注销当前注册表回调
    if (0 < g_liRegCookie.QuadPart)
    {
        CmUnRegisterCallback(g_liRegCookie);
    }

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
RegistryFilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("RegistryFilter!RegistryFilterPreOperation: Entered\n"));

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (RegistryFilterDoRequestOperationStatus(Data)) {

        status = FltRequestOperationStatusCallback(Data,
            RegistryFilterOperationStatusCallback,
            (PVOID)(++OperationStatusCtx));
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                ("RegistryFilter!RegistryFilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                    status));
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
RegistryFilterOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
)
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("RegistryFilter!RegistryFilterOperationStatusCallback: Entered\n"));

    PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
        ("RegistryFilter!RegistryFilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
            OperationStatus,
            RequesterContext,
            ParameterSnapshot->MajorFunction,
            ParameterSnapshot->MinorFunction,
            FltGetIrpName(ParameterSnapshot->MajorFunction)));
}


FLT_POSTOP_CALLBACK_STATUS
RegistryFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("RegistryFilter!RegistryFilterPostOperation: Entered\n"));

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
RegistryFilterPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("RegistryFilter!RegistryFilterPreOperationNoPostOperation: Entered\n"));

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
RegistryFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

        //
        //  Check for oplock operations
        //

        (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
            ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

            ||

            //
            //    Check for directy change notification
            //

            ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
                (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
            );
}
