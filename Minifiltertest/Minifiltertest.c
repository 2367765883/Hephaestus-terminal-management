#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <string.h>
#include "util.h"

#define  SYB_LOCATION 23 //位置

#define  MAX_SCAN_SIZE 2097152 //最大扫描2M

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

/** 向前声明 */
NTKERNELAPI
UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

struct {
    PDRIVER_OBJECT DriverObject;
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PEPROCESS UserProcess;
    ULONG PID;
    PFLT_PORT ClientPort;
} gMessage;


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT(_dbgLevel, _string) DbgPrint _string

/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
FsMiniFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
FsMiniFilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
FsMiniFilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
FsMiniFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
FsMiniFilterInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperationWithBlocker(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID
FsMiniFilterOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
FsMiniFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

BOOLEAN
FsMiniFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsMiniFilterUnload)
#pragma alloc_text(PAGE, FsMiniFilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, FsMiniFilterInstanceSetup)
#pragma alloc_text(PAGE, FsMiniFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, FsMiniFilterInstanceTeardownComplete)
#endif





FLT_POSTOP_CALLBACK_STATUS
PreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{


	
  
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
PreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
 //   NTSTATUS status;
	//PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
	//status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pNameInfo);

	//if (NT_SUCCESS(status)) {
	//	status = FltParseFileNameInformation(pNameInfo);
	//	if (NT_SUCCESS(status)) {
	//		ANSI_STRING strFileName, strVolume;
	//		RtlUnicodeStringToAnsiString(&strFileName, &(pNameInfo->Name), TRUE);
	//		RtlUnicodeStringToAnsiString(&strVolume, &(pNameInfo->Volume), TRUE);


	//		FILE_STANDARD_INFORMATION fileInfo;
	//		ULONG infoLength;
	//		status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, &fileInfo
	//			, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &infoLength);

	//		ULONG ProcessId = FltGetRequestorProcessId(Data);
	//		UCHAR uTmpFilename[256] = { 0 };
	//		UCHAR* UserPathPart = &strFileName.Buffer[SYB_LOCATION];

	//		PEPROCESS TargProcess;
	//		UCHAR* uchProName = NULL;

	//		status = PsLookupProcessByProcessId(ProcessId, &TargProcess);

	//		if (NT_SUCCESS(status))
	//		{
	//			uchProName = PsGetProcessImageFileName(TargProcess);
	//		}

	//		if (uchProName != 0)
	//		{


	//			if (
	//				gMessage.ClientPort != NULL
	//				&& ProcessId != gMessage.PID
	//				&& ProcessId != 4
	//				&& strstr(uchProName, "yara") == NULL
	//				&& strstr(uchProName, "explorer") == NULL
	//				&& strstr(uchProName, "conhost") == NULL
	//				&& strstr(uchProName, "ctfmon") == NULL
	//				&& strstr(uchProName, "csrss") == NULL
	//				&& strstr(uchProName, "dllhost") == NULL
	//				&& strstr(uchProName, "lsass") == NULL
	//				&& strstr(uchProName, "dwm") == NULL
	//				&& strstr(uchProName, "svchost") == NULL
	//				&& strstr(uchProName, "wininit") == NULL
	//				&& strstr(uchProName, "winlogon") == NULL
	//				&& strstr(uchProName, "msvsmon") == NULL//远程调试
	//				)
	//			{
	//				ULONG reqLength = sizeof(MESSAGE_REQ);
	//				ULONG replyLength = sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER);

	//				PMESSAGE_REQ reqBuffer = ExAllocatePoolWithTag(NonPagedPool, reqLength, 'nacS');
	//				PMESSAGE_REPLY replyBuffer = ExAllocatePoolWithTag(NonPagedPool, replyLength, 'nacS');



	//				if (reqBuffer == NULL) {
	//					Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
	//					Data->IoStatus.Information = 0;
	//					return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	//				}

	//				switch (strFileName.Buffer[SYB_LOCATION - 1])
	//				{
	//				case '3':
	//				{

	//					RtlCopyMemory(uTmpFilename, "C:", strlen("C:"));
	//					RtlCopyMemory(uTmpFilename + 2, UserPathPart, strlen(UserPathPart));
	//					break;
	//				}
	//				case '4':
	//				{
	//					RtlCopyMemory(uTmpFilename, "D:", strlen("D:"));
	//					RtlCopyMemory(uTmpFilename + 2, UserPathPart, strlen(UserPathPart));
	//					break;
	//				}
	//				case '5':
	//				{
	//					RtlCopyMemory(uTmpFilename, "E:", strlen("E:"));
	//					RtlCopyMemory(uTmpFilename + 2, UserPathPart, strlen(UserPathPart));
	//					break;
	//				}
	//				default:
	//					break;
	//				}


	//				RtlZeroMemory(replyBuffer, replyLength);

	//				RtlZeroMemory(reqBuffer->Filename, 512);
	//				RtlCopyMemory(reqBuffer->Filename, uTmpFilename, strlen(uTmpFilename));

	//				if (strstr(reqBuffer->Filename, "Monitor"))
	//				{
	//					DbgPrint("ous:%d----%s\n", reqLength, reqBuffer->Filename);
	//				}

	//				status = FltSendMessage(gMessage.Filter, &gMessage.ClientPort, reqBuffer
	//					, reqLength, replyBuffer, &replyLength, NULL);



	//				if (*(char*)replyBuffer == 1)//99方便调试测试
	//				{
	//					//FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
	//					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	//					Data->IoStatus.Information = 0;
	//					return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	//				}

	//				if (STATUS_SUCCESS != status)
	//					DbgPrint("!!! couldn't send message to user-mode to scan file, status 0x%X\n", status);

	//				ExFreePoolWithTag(reqBuffer, 'nacS');
	//				ExFreePoolWithTag(replyBuffer, 'nacS');
	//			}

	//		}

	//		ObDereferenceObject(TargProcess);

	//		RtlFreeAnsiString(&strFileName);
	//		RtlFreeAnsiString(&strVolume);
	//	}
	//	FltReleaseFileNameInformation(pNameInfo);
	//}

	//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("END READ\n\n"));
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
	
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pNameInfo);

	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(pNameInfo);
		if (NT_SUCCESS(status)) {
			ANSI_STRING strFileName, strVolume;
			RtlUnicodeStringToAnsiString(&strFileName, &(pNameInfo->Name), TRUE);
			RtlUnicodeStringToAnsiString(&strVolume, &(pNameInfo->Volume), TRUE);


			FILE_STANDARD_INFORMATION fileInfo;
			ULONG infoLength;
			status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, &fileInfo
				, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &infoLength);

			ULONG ProcessId = FltGetRequestorProcessId(Data);
			UCHAR uTmpFilename[256] = { 0 };
			UCHAR* UserPathPart = &strFileName.Buffer[SYB_LOCATION];

			PEPROCESS TargProcess;
			UCHAR* uchProName = NULL;

			status = PsLookupProcessByProcessId(ProcessId, &TargProcess);

			if (NT_SUCCESS(status))
			{
				uchProName = PsGetProcessImageFileName(TargProcess);
			}

			if (uchProName != 0)
			{


				if (
					gMessage.ClientPort != NULL
					&& ProcessId != gMessage.PID
					&& ProcessId != 4
					&& strstr(uchProName, "yara") == NULL
					&& strstr(uchProName, "explorer") == NULL
					&& strstr(uchProName, "conhost") == NULL
					&& strstr(uchProName, "ctfmon") == NULL
					&& strstr(uchProName, "csrss") == NULL
					&& strstr(uchProName, "dllhost") == NULL
					&& strstr(uchProName, "lsass") == NULL
					&& strstr(uchProName, "dwm") == NULL
					&& strstr(uchProName, "svchost") == NULL
					&& strstr(uchProName, "wininit") == NULL
					&& strstr(uchProName, "winlogon") == NULL
                    && strstr(uchProName, "msvsmon") == NULL//远程调试
                    && strstr(uchProName, "RegFltMessager") == NULL//远程调试
					)
				{
					ULONG reqLength = sizeof(MESSAGE_REQ);
					ULONG replyLength = sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER);

					PMESSAGE_REQ reqBuffer = ExAllocatePoolWithTag(NonPagedPool, reqLength, 'nacS');
					PMESSAGE_REPLY replyBuffer = ExAllocatePoolWithTag(NonPagedPool, replyLength, 'nacS');



					if (reqBuffer == NULL) {
						Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
						Data->IoStatus.Information = 0;
						return FLT_POSTOP_FINISHED_PROCESSING;
					}

					switch (strFileName.Buffer[SYB_LOCATION - 1])
					{
					case '3':
					{

						RtlCopyMemory(uTmpFilename, "C:", strlen("C:"));
						RtlCopyMemory(uTmpFilename + 2, UserPathPart, strlen(UserPathPart));
						break;
					}
					case '4':
					{
						RtlCopyMemory(uTmpFilename, "D:", strlen("D:"));
						RtlCopyMemory(uTmpFilename + 2, UserPathPart, strlen(UserPathPart));
						break;
					}
					case '5':
					{
						RtlCopyMemory(uTmpFilename, "E:", strlen("E:"));
						RtlCopyMemory(uTmpFilename + 2, UserPathPart, strlen(UserPathPart));
						break;
					}
					default:
						break;
					}


					RtlZeroMemory(replyBuffer, replyLength);

					RtlZeroMemory(reqBuffer->Filename, 512);
					RtlCopyMemory(reqBuffer->Filename, uTmpFilename, strlen(uTmpFilename));

					if (strstr(reqBuffer->Filename, "Monitor"))
					{
						DbgPrint("ous:%d----%s\n", reqLength,reqBuffer->Filename);
					}

                    reqBuffer->uPid = ProcessId;

					status = FltSendMessage(gMessage.Filter, &gMessage.ClientPort, reqBuffer
						, reqLength, replyBuffer, &replyLength, NULL);



					if (*(char*)replyBuffer == 99)//99方便调试测试
					{
						FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
						Data->IoStatus.Status = STATUS_ACCESS_DENIED;
						Data->IoStatus.Information = 0;
						return FLT_POSTOP_FINISHED_PROCESSING;
					}

					if (STATUS_SUCCESS != status)
						DbgPrint("!!! couldn't send message to user-mode to scan file, status 0x%X\n", status);

					ExFreePoolWithTag(reqBuffer, 'nacS');
					ExFreePoolWithTag(replyBuffer, 'nacS');
				}

			}

			ObDereferenceObject(TargProcess);

			RtlFreeAnsiString(&strFileName);
			RtlFreeAnsiString(&strVolume);
		}
		FltReleaseFileNameInformation(pNameInfo);
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("END READ\n\n"));
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
   
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}






//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_READ,
    0,
    PreRead,
    FsMiniFilterPostOperation},

    { IRP_MJ_WRITE,
    0,
    FsMiniFilterPreOperation,
    FsMiniFilterPostOperation },

    { IRP_MJ_CREATE,
      0,
      FsMiniFilterPreOperation,
      PostCreate },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_CLOSE,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      PreSetInfo,
      FsMiniFilterPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_SET_EA,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },
#if 0
    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      FsMiniFilterPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_PNP,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      FsMiniFilterPreOperation,
      FsMiniFilterPostOperation },

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

    FsMiniFilterUnload,                           //  MiniFilterUnload

    FsMiniFilterInstanceSetup,                    //  InstanceSetup
    FsMiniFilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    FsMiniFilterInstanceTeardownStart,            //  InstanceTeardownStart
    FsMiniFilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
FsMiniFilterInstanceSetup(
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
        ("FsMiniFilter!FsMiniFilterInstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}


NTSTATUS
FsMiniFilterInstanceQueryTeardown(
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
        ("FsMiniFilter!FsMiniFilterInstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}


VOID
FsMiniFilterInstanceTeardownStart(
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
        ("FsMiniFilter!FsMiniFilterInstanceTeardownStart: Entered\n"));
}


VOID
FsMiniFilterInstanceTeardownComplete(
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
        ("FsMiniFilter!FsMiniFilterInstanceTeardownComplete: Entered\n"));
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
FsMiniFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsMiniFilter!FsMiniFilterUnload: Entered\n"));

    FltCloseCommunicationPort(gMessage.ServerPort);
    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}







FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    NTSTATUS status;

    if (FsMiniFilterDoRequestOperationStatus(Data)) {
        status = FltRequestOperationStatusCallback(Data,
            FsMiniFilterOperationStatusCallback,
            (PVOID)(++OperationStatusCtx));

        if (!NT_SUCCESS(status)) {
            PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                ("FsMiniFilter!FsMiniFilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                    status));
        }
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperationWithBlocker(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    NTSTATUS status;

    if (gMessage.ClientPort != NULL) {
        ULONG reqLength = sizeof(MESSAGE_REQ);
        ULONG replyLength = sizeof(MESSAGE_REPLY) + sizeof(FILTER_REPLY_HEADER);

        PMESSAGE_REQ reqBuffer = ExAllocatePoolWithTag(NonPagedPool, reqLength, 'nacS');
        PMESSAGE_REPLY replyBuffer = ExAllocatePoolWithTag(NonPagedPool, replyLength, 'nacS');

        if (reqBuffer == NULL) {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

       /* reqBuffer->Type = OTHER;
        reqBuffer->PID = FltGetRequestorProcessId(Data);*/
        reqBuffer->Filename[0] = 0;

        /*status = FltSendMessage(gMessage.Filter, &gMessage.ClientPort, reqBuffer,
            reqLength, replyBuffer, &replyLength, NULL);

        if (status != STATUS_SUCCESS) {
            DbgPrint("!!! (OTHER ERROR) STATUS: 0x%X\n", status);
        }
        else {
            if (!replyBuffer->IsSafe && !FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
                DbgPrint("BLOCKING.\n");
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }*/
    }

    if (FsMiniFilterDoRequestOperationStatus(Data)) {
        status = FltRequestOperationStatusCallback(Data,
            FsMiniFilterOperationStatusCallback,
            (PVOID)(++OperationStatusCtx));

        if (!NT_SUCCESS(status)) {
            PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                ("FsMiniFilter!FsMiniFilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                    status));
        }
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
FsMiniFilterOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
) {
    UNREFERENCED_PARAMETER(FltObjects);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsMiniFilter!FsMiniFilterOperationStatusCallback: Entered\n"));

    PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
        ("FsMiniFilter!FsMiniFilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
            OperationStatus,
            RequesterContext,
            ParameterSnapshot->MajorFunction,
            ParameterSnapshot->MinorFunction,
            FltGetIrpName(ParameterSnapshot->MajorFunction)));
}


FLT_POSTOP_CALLBACK_STATUS
FsMiniFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperationNoPostOperation(
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
        ("FsMiniFilter!FsMiniFilterPreOperationNoPostOperation: Entered\n"));

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
FsMiniFilterDoRequestOperationStatus(
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
