#include "tool.h"
ULONG64 uOrgValidAccessMask = 0;
HANDLE PidArray[10] = { 0 };
CHAR* DllArray[DLL_NUM];
CHAR *IPs[IP_NUM];
ZWDELETEFILE ZwDeleteFilePtr = NULL;
UNICODE_STRING  unImgFileName;
PVOID pObHandle = NULL;
UNICODE_STRING unFileNames[FILE_NUM];
UNICODE_STRING unBlackProcessName[FILE_NUM];

POBJECT_TYPE* IoDriverObjectType = NULL; 

RTL_OSVERSIONINFOW osinfo = {0};
PDRIVER_OBJECT g_PDriver = NULL;
UNICODE_STRING g_FltRegPath = { 0 };

NTSTATUS FD_SetFileCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
)
{
	Irp->UserIosb->Status = Irp->IoStatus.Status;
	Irp->UserIosb->Information = Irp->IoStatus.Information;

	KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);

	IoFreeIrp(Irp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

HANDLE  FD_OpenFile(WCHAR szFileName[])
{
	NTSTATUS            ntStatus;
	UNICODE_STRING      FileName;
	OBJECT_ATTRIBUTES   objectAttributes;
	HANDLE              hFile;
	IO_STATUS_BLOCK     ioStatus;

	// ȷ��IRQL��PASSIVE_LEVEL�� 
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return NULL;

	// ��ʼ���ļ��� 
	RtlInitUnicodeString(&FileName, szFileName);
	DbgPrint("%ws", FileName.Buffer);

	//��ʼ���������� 
	InitializeObjectAttributes(&objectAttributes, &FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	// ���ļ� 
	ntStatus = IoCreateFile(&hFile, FILE_READ_ATTRIBUTES, &objectAttributes, &ioStatus,
		0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(ntStatus))
		return NULL;

	return  hFile;
}

BOOLEAN FD_StripFileAttributes(HANDLE FileHandle)
{
	NTSTATUS                ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT            fileObject;
	PDEVICE_OBJECT          DeviceObject;
	PIRP                    Irp;
	KEVENT                  SycEvent;
	FILE_BASIC_INFORMATION  FileInformation;
	IO_STATUS_BLOCK         ioStatus;
	PIO_STACK_LOCATION      irpSp;

	// ��ȡ�ļ����� 
	ntStatus = ObReferenceObjectByHandle(FileHandle, DELETE,
		*IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ObReferenceObjectByHandle error!");
		return FALSE;
	}

	// ��ȡ��ָ���ļ�������������豸���� 
	DeviceObject = IoGetRelatedDeviceObject(fileObject);

	// ����IRP 
	Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
	if (Irp == NULL)
	{
		ObDereferenceObject(fileObject);

		DbgPrint("FD_StripFileAttributes IoAllocateIrp error");
		return FALSE;
	}

	// ��ʼ��ͬ���¼����� 
	KeInitializeEvent(&SycEvent, SynchronizationEvent, FALSE);

	memset(&FileInformation, 0, 0x28);
	FileInformation.FileAttributes = FILE_ATTRIBUTE_NORMAL;

	// ��ʼ��IRP 
	Irp->AssociatedIrp.SystemBuffer = &FileInformation;
	Irp->UserEvent = &SycEvent;
	Irp->UserIosb = &ioStatus;
	Irp->Tail.Overlay.OriginalFileObject = fileObject;
	Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;

	// ����IRP��ջ��Ϣ 
	irpSp = IoGetNextIrpStackLocation(Irp);
	irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = fileObject;
	irpSp->Parameters.SetFile.Length = sizeof(FILE_BASIC_INFORMATION);
	irpSp->Parameters.SetFile.FileInformationClass = FileBasicInformation;
	irpSp->Parameters.SetFile.FileObject = fileObject;

	// ����������� 
	IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);

	// �ɷ�IRP 
	IoCallDriver(DeviceObject, Irp);

	// �ȴ�IRP����� 
	KeWaitForSingleObject(&SycEvent, Executive, KernelMode, TRUE, NULL);

	// �ݼ����ü��� 
	ObDereferenceObject(fileObject);

	return TRUE;
}

BOOLEAN FD_DeleteFile(HANDLE FileHandle)
{
	NTSTATUS          ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT      fileObject;
	PDEVICE_OBJECT    DeviceObject;
	PIRP              Irp;
	KEVENT            SycEvent;
	FILE_DISPOSITION_INFORMATION    FileInformation;
	IO_STATUS_BLOCK                 ioStatus;
	PIO_STACK_LOCATION              irpSp;
	PSECTION_OBJECT_POINTERS        pSectionObjectPointer;

	// ��ȡ�ļ����� 
	ntStatus = ObReferenceObjectByHandle(FileHandle, DELETE,
		*IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ObReferenceObjectByHandle error!");
		return FALSE;
	}

	// ��ȡ��ָ���ļ�������������豸���� 
	DeviceObject = IoGetRelatedDeviceObject(fileObject);

	// ����IRP 
	Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
	if (Irp == NULL)
	{
		ObDereferenceObject(fileObject);
		DbgPrint("FD_DeleteFile IoAllocateIrp error");
		return FALSE;
	}

	// ��ʼ��ͬ���¼����� 
	KeInitializeEvent(&SycEvent, SynchronizationEvent, FALSE);

	FileInformation.DeleteFile = TRUE;

	// ��ʼ��IRP 
	Irp->AssociatedIrp.SystemBuffer = &FileInformation;
	Irp->UserEvent = &SycEvent;
	Irp->UserIosb = &ioStatus;
	Irp->Tail.Overlay.OriginalFileObject = fileObject;
	Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;

	// ����IRP��ջ 
	irpSp = IoGetNextIrpStackLocation(Irp);
	irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = fileObject;
	irpSp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
	irpSp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
	irpSp->Parameters.SetFile.FileObject = fileObject;

	// ����������� 
	IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);

	// ���û����3�У����޷�ɾ���������е��ļ� 
	pSectionObjectPointer = fileObject->SectionObjectPointer;
	pSectionObjectPointer->ImageSectionObject = 0;
	pSectionObjectPointer->DataSectionObject = 0;

	// �ɷ�IRP 
	IoCallDriver(DeviceObject, Irp);

	// �ȴ�IRP��� 
	KeWaitForSingleObject(&SycEvent, Executive, KernelMode, TRUE, NULL);

	// �ݼ����ü��� 
	ObDereferenceObject(fileObject);

	return TRUE;
}

BOOLEAN ForceDeleteFiles(WCHAR szFileName[])
{
	HANDLE      hFile = NULL;
	BOOLEAN     status = FALSE;

	__try {
		// ���ļ� 
		if ((hFile = FD_OpenFile(szFileName)) == NULL)
		{
			DbgPrint("FD_OpenFile error!");
			return FALSE;
		}

		// //ȥ��ֻ�����ԣ�����ɾ��ֻ���ļ� 
		if (FD_StripFileAttributes(hFile) == FALSE)
		{
			ZwClose(hFile);
			DbgPrint("FD_StripFileAttributes error!");
			return FALSE;
		}

		// ɾ���ļ� 
		status = FD_DeleteFile(hFile);
		ZwClose(hFile);

		return status;

	}
	__except (1) {
		DbgPrint("execption!");
	}

	return FALSE;
}









OB_PREOP_CALLBACK_STATUS FileCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNICODE_STRING DosName;
	PFILE_OBJECT fileo = (PFILE_OBJECT)OperationInformation->Object;
	HANDLE CurrentProcessId = PsGetCurrentProcessId();
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OperationInformation->ObjectType != *IoFileObjectType)
	{
		return OB_PREOP_SUCCESS;
	}

	// ������Чָ��
	if (fileo->FileName.Buffer == NULL ||
		!MmIsAddressValid(fileo->FileName.Buffer) ||
		fileo->DeviceObject == NULL ||
		!MmIsAddressValid(fileo->DeviceObject))
	{
		return OB_PREOP_SUCCESS;
	}

	// ������Ч·��
	if (!_wcsicmp(fileo->FileName.Buffer, L"\\Endpoint") ||
		!_wcsicmp(fileo->FileName.Buffer, L"?") ||
		!_wcsicmp(fileo->FileName.Buffer, L"\\.\\.") ||
		!_wcsicmp(fileo->FileName.Buffer, L"\\"))
	{
		return OB_PREOP_SUCCESS;
	}
	//DbgPrintEx(77,0,"[db]wenjianwenjianwenjian%wZ\n", fileo->FileName);
	for (size_t i = 0; i < FILE_NUM; i++)
	{
		
		if (wcslen(unFileNames[i].Buffer) > 2)
		{
			//DbgPrintEx(77, 0, "[db]�ص�����:%wZ\n", unFileNames[i]);
			if (wcsstr(_wcslwr(fileo->FileName.Buffer), unFileNames[i].Buffer))
			{
				if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				}
				if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
				{
					OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
				}
				//DbgPrint("[db]DenySuccessfully \n");
				break;
			}
		}

	}
	return OB_PREOP_SUCCESS;

}

VOID EnableObType(POBJECT_TYPE ObjectType)
{
	PMY_OBJECT_TYPE myobtype = (PMY_OBJECT_TYPE)ObjectType;
	myobtype->TypeInfo.SupportsObjectCallbacks = 1;
}

VOID InitFileFilter(PDRIVER_OBJECT pDriver)
{
	for (size_t i = 0; i < FILE_NUM; i++)
	{
		unBlackProcessName[i].Length = 0;
		unBlackProcessName[i].MaximumLength = 256;
		unBlackProcessName[i].Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 256, MEM_TAG2); //MEM_TAGΪ�Զ���
		RtlZeroMemory(unBlackProcessName[i].Buffer, unBlackProcessName[i].MaximumLength);
	}
	for (size_t i = 0; i < FILE_NUM; i++)
	{
		unFileNames[i].Length = 0;
		unFileNames[i].MaximumLength = 256;
		unFileNames[i].Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 256, MEM_TAG); //MEM_TAGΪ�Զ���
		RtlZeroMemory(unFileNames[i].Buffer, unFileNames[i].MaximumLength);
	}
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA ldr;
	OB_CALLBACK_REGISTRATION obRegFileCallBack;
	OB_OPERATION_REGISTRATION opRegFileCallBack;

	// enable IoFileObjectType
	EnableObType(*IoFileObjectType);

	// bypass MmVerifyCallbackFunction
	ldr = (PLDR_DATA)pDriver->DriverSection;
	ldr->Flags |= 0x20;

	// ��ʼ���ص�
	memset(&obRegFileCallBack, 0, sizeof(obRegFileCallBack));
	obRegFileCallBack.Version = ObGetFilterVersion();
	obRegFileCallBack.OperationRegistrationCount = 1;
	obRegFileCallBack.RegistrationContext = NULL;
	RtlInitUnicodeString(&obRegFileCallBack.Altitude, L"321000");
	obRegFileCallBack.OperationRegistration = &opRegFileCallBack;

	memset(&opRegFileCallBack, 0, sizeof(opRegFileCallBack));
	opRegFileCallBack.ObjectType = IoFileObjectType;
	opRegFileCallBack.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opRegFileCallBack.PreOperation = (POB_PRE_OPERATION_CALLBACK)&FileCallBack;

	status = ObRegisterCallbacks(&obRegFileCallBack, &pObHandle);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("ע��ص����� \n");
		status = STATUS_UNSUCCESSFUL;
	}
}

VOID UnloadFileFilter()
{
	PVOID pObA = pObHandle;
	ObUnRegisterCallbacks(pObA);
}




//����������
PVOID SearchSpecialCode(PVOID pSearchBeginAddr, ULONG ulSearchLength, PUCHAR pSpecialCode, ULONG ulSpecialCodeLength)
{
	PVOID pDestAddr = NULL;
	PUCHAR pBeginAddr = (PUCHAR)pSearchBeginAddr;
	PUCHAR pEndAddr = pBeginAddr + ulSearchLength;
	PUCHAR i = NULL;
	ULONG j = 0;
	for (i = pBeginAddr; i <= pEndAddr; i++)
	{
		for (j = 0; j < ulSpecialCodeLength; j++)
		{
			if (FALSE == MmIsAddressValid((PVOID)(i + j)))
			{
				break;
			}
			if (*(PUCHAR)(i + j) != pSpecialCode[j])
			{
				break;
			}
		}
		if (j >= ulSpecialCodeLength)
		{
			pDestAddr = (PVOID)i;
			break;
		}
	}
	return pDestAddr;
}
//ģ����Ϣ��ȡ
ULONG_PTR GetKernelModuleBase(PUCHAR moduleName, PULONG pModuleSize) {
	RTL_PROCESS_MODULES SysModules = { 0 };
	PRTL_PROCESS_MODULES pModules = &SysModules;
	ULONG SystemInformationLength = 0;
	//��ѯϵͳ�������ں�ģ�飬�ײ�Ҳ�Ǳ�������
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, pModules, sizeof(RTL_PROCESS_MODULES), &SystemInformationLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		pModules = ExAllocatePool(NonPagedPool, SystemInformationLength + sizeof(RTL_PROCESS_MODULES));
		RtlZeroMemory(pModules, SystemInformationLength + sizeof(RTL_PROCESS_MODULES));
		status = ZwQuerySystemInformation(SystemModuleInformation, pModules, SystemInformationLength + sizeof(RTL_PROCESS_MODULES), &SystemInformationLength);
		if (!NT_SUCCESS(status)) {
			ExFreePool(pModules);
			return 0;
		}
	}
	if (!strcmp("ntoskrnl.exe", moduleName) || !strcmp("ntkrnlpa.exe", moduleName)) {
		*pModuleSize = pModules->Modules[0].ImageSize;
		ULONG_PTR ret = pModules->Modules[0].ImageBase;
		if (SystemInformationLength) {
			ExFreePool(pModules);
		}
		return ret;
	}
	for (ULONG i = 0; i < pModules->NumberOfModules; i++) {
		if (strstr(pModules->Modules[i].FullPathName, moduleName)) {
			*pModuleSize = pModules->Modules[i].ImageSize;
			ULONG_PTR ret = pModules->Modules[i].ImageBase;
			if (SystemInformationLength) {
				ExFreePool(pModules);
			}
			//����ģ���ַ
			return ret;
		}
	}
	if (SystemInformationLength) {
		ExFreePool(pModules);
	}
	return 0;
}
//�������ҵ�������ַ
PVOID GetNtFuncAddr(unsigned char* NtFuncShellCode, ULONG uFuncCodeLen)
{
	ULONG uNtoskrnlSize = 0;
	PVOID pNtoskrnlBase = NULL;
	PVOID pNeedFuncAddr = NULL;
	pNtoskrnlBase = GetKernelModuleBase("ntoskrnl.exe", &uNtoskrnlSize);
	pNeedFuncAddr = SearchSpecialCode(pNtoskrnlBase, uNtoskrnlSize, NtFuncShellCode, uFuncCodeLen);
	pNeedFuncAddr = (PUCHAR)pNeedFuncAddr;
	return pNeedFuncAddr;
}
//���DbgkDebugObjectType��ַ
PVOID GetDebugTypeAddr()
{
	PVOID DebugTypeOffsetAddr = NULL;
	PVOID DebugTypeAddr = NULL;
	int DebugObjOffset = 0;
	ULONG DebugObjectType = 0;
	unsigned char NtDbgkDebugObjectTypeCode[] =
	{
			0x48, 0x8B, 0x5C, 0x24, 0x58, 0xC7, 0x43, 0x18, 0x01, 0x00,
		    0x00, 0x00, 0x48, 0x83, 0x63, 0x20, 0x00, 0x83, 0x63, 0x28,
		    0x00, 0x48, 0x8D, 0x4B, 0x30, 0x45, 0x33, 0xC0, 0x41, 0x8D,
		    0x50, 0x01
	};
	DebugTypeOffsetAddr =  (PUCHAR)GetNtFuncAddr(NtDbgkDebugObjectTypeCode, 32) - 0x3c +0x3;
	DebugObjOffset = *(int*)DebugTypeOffsetAddr;
	DebugTypeAddr = (PUCHAR)DebugTypeOffsetAddr + 0x7-0x3 + DebugObjOffset;
	return DebugTypeAddr;
}

VOID DisableDebugThread()
{
	PVOID DebugTypeAddr = NULL;
	PVOID uDebugTypeObject = 0;
	POBJECT_TYPE DebugObject = NULL;
	POBJECT_TYPE_INITIALIZER DebugObjectInitial = NULL;
	ULONG64 ValidAccessMask = 0;
	ULONG NeedValidAccessMask = 0;
	DebugTypeAddr = GetDebugTypeAddr();
	uDebugTypeObject = *(ULONG64*)DebugTypeAddr;
	DebugObject = uDebugTypeObject;
	DebugObjectInitial = (ULONG64)((PUCHAR)DebugObject + 0x40);
	ValidAccessMask = DebugObjectInitial->ValidAccessMask;
	uOrgValidAccessMask = 0x1f000f;
	RtlCopyMemory(&(DebugObjectInitial->ValidAccessMask),&NeedValidAccessMask,sizeof(ULONG));
	
}


VOID EnbleDebugThread()
{
	PVOID DebugTypeAddr = NULL;
	PVOID uDebugTypeObject = 0;
	POBJECT_TYPE DebugObject = NULL;
	POBJECT_TYPE_INITIALIZER DebugObjectInitial = NULL;
	ULONG NeedValidAccessMask = uOrgValidAccessMask;
	DebugTypeAddr = GetDebugTypeAddr();
	uDebugTypeObject = *(ULONG64*)DebugTypeAddr;
	DebugObject = uDebugTypeObject;
	DebugObjectInitial = (ULONG64)((PUCHAR)DebugObject + 0x40);
	RtlCopyMemory(&(DebugObjectInitial->ValidAccessMask), &NeedValidAccessMask, sizeof(ULONG));
}


VOID InitDriver(PDRIVER_OBJECT pDriver)
{
	

	InitFileFilter(pDriver);
	PsSetCreateProcessNotifyRoutineEx(CreateProcessCallBack, FALSE);
	NTSTATUS status;
	PDEVICE_OBJECT pDevice = NULL;
	UNICODE_STRING uDeciceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING uSyb_Name = RTL_CONSTANT_STRING(SYMBOLIC_NAME);

	status = IoCreateDevice(pDriver, 0, &uDeciceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevice);
	if (!NT_SUCCESS(status))
	{
		//DbgPrintEx(77, 0, "CreateDeviceFaild\n");
	}

	status = IoCreateSymbolicLink(&uSyb_Name, &uDeciceName);
	if (!NT_SUCCESS(status))
	{
		//DbgPrintEx(77, 0, "CreateSysbolinkFaild\n");
	}

	pDevice->Flags |= DO_BUFFERED_IO;
	pDriver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;

}


NTSTATUS DispatchControl(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	PVOID pBuff = pIrp->AssociatedIrp.SystemBuffer;
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG CtlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
	switch (CtlCode)
	{
	case CTL_BLOCK_IP:
	{
		CHAR* ipaddress = pBuff;
		break;
	}
	case CTL_PROT:
	{
		HANDLE pid = (HANDLE)atoi(pBuff);
		for (size_t i = 0; i < PROCESS_NUM; i++)
		{
			PEPROCESS targetProcess;
			NTSTATUS status = PsLookupProcessByProcessId(PidArray[i], &targetProcess);
			if (NT_SUCCESS(status)) {
				ObDereferenceObject(targetProcess);
			}
			else {
				PidArray[i] = 0;
			}
			if (PidArray[i]==0)
			{
				PidArray[i] = pid;
				break;
			}
		}
		break;
	}
	case CTL_UNPROT:
	{
		HANDLE pid = (HANDLE)atoi(pBuff);
		for (size_t i = 0; i < PROCESS_NUM; i++)
		{
			PEPROCESS targetProcess;
			NTSTATUS status = PsLookupProcessByProcessId(PidArray[i], &targetProcess);
			if (NT_SUCCESS(status)) {
				ObDereferenceObject(targetProcess);
			}
			else {
				PidArray[i] = 0;
			}
			if (PidArray[i] == pid)
			{
				PidArray[i] = 0;
				break;
			}
		}
		break;
	}
	case CTL_KILL:
	{
		ULONG pid = atoi(pBuff);
		KillProcess(pid);
		break;
	}
	case CTL_ADDDLL:
	{
		UNICODE_STRING unFileName = ConvertToUnicodeString((char*)pBuff);
		for (size_t i = 0; i < FILE_NUM; i++)
		{
			if (wcslen(unBlackProcessName[i].Buffer) < 2)
			{
				RtlUnicodeStringPrintf(&unBlackProcessName[i], unFileName.Buffer);
				break;
			}
		}
		break;
	}
	case CTL_DELDLL:
	{
		UNICODE_STRING unFileName = ConvertToUnicodeString((char*)pBuff);
		for (size_t i = 0; i < FILE_NUM; i++)
		{
			if (!RtlCompareUnicodeString(&unFileName, &unBlackProcessName[i], FALSE))
			{
				RtlZeroMemory(unBlackProcessName[i].Buffer, unBlackProcessName[i].MaximumLength);
			}
		}
		break;
	}
	case CTL_DELFILE:
	{
		char buf[260] = { 0 };
		RtlCopyMemory(buf,"\\DosDevices\\",strlen("\\DosDevices\\"));
		strcat(buf, pBuff);
		UNICODE_STRING targetFile;
		targetFile = ConvertToUnicodeString(buf);
		DbgPrint("[DBS]%s\n", buf);
		ForceDeleteFiles(targetFile.Buffer);
		ZwDeleteFilePtr = NULL;
		break;
	}
	case CTL_PROTECT_FILE:
	{
		char buf[260] = { 0 };
		RtlCopyMemory(buf, "\\DosDevices\\", strlen("\\DosDevices\\"));
		ProtectFile((const char*)buf);
		break;
	}
	case CTL_DISABLE_DEBUG:
	{
		DisableDebugThread();
		break;
	}
	case CTL_ENABLE_DEBUG:
	{
		EnbleDebugThread();
		break;
	}
	case CTL_ADDFILE:
	{
		UNICODE_STRING unFileName = ConvertToUnicodeString((char*)pBuff);
		for (size_t i = 0; i < FILE_NUM; i++)
		{
			if (wcslen(unFileNames[i].Buffer) < 2)
			{
				RtlUnicodeStringPrintf(&unFileNames[i], unFileName.Buffer);
				break;
			}
		}
		break;
	}
	case CTL_DELFILENAME:
	{
		UNICODE_STRING unFileName = ConvertToUnicodeString((char*)pBuff);
		for (size_t i = 0; i < FILE_NUM; i++)
		{
			if (!RtlCompareUnicodeString(&unFileName, &unFileNames[i], FALSE))
			{
				RtlZeroMemory(unFileNames[i].Buffer, unFileNames[i].MaximumLength);
				break;
			}
		}
		break;
	};
	case CTL_BLOCKUSB:
	{
		StartFltWpd(g_PDriver,&g_FltRegPath);
		break;
	}
	case CTL_ALLOWUSB:
	{
		unloadWpdFlt(g_PDriver);
		break;
	}
	default:
		break;
	}
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	DbgPrint("Create!");
	//����IRP�����Ѿ��ɹ���
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	//���ض����ֽڵ�����
	pIrp->IoStatus.Information = 0;
	//����IRP��������
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	//�������óɹ�
	return STATUS_SUCCESS;
}


DWORD HandleToPid(IN HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS st = 0;
	st = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
	if (NT_SUCCESS(st))
	{
		return (DWORD)pbi.UniqueProcessId;
	}
	return 0;
}


BOOLEAN  KillProcess(ULONG PID)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	int i = 0;
	PVOID handle;
	PEPROCESS Eprocess;
	ntStatus = PsLookupProcessByProcessId(PID, &Eprocess);
	if (NT_SUCCESS(ntStatus))
	{
		KeAttachProcess(Eprocess);
		for (i = 0; i <= 0x7fffffff; i += 0x1000)
		{
			if (MmIsAddressValid((PVOID)i))
			{
				_try
				{
				ProbeForWrite((PVOID)i, 0x1000, sizeof(ULONG));
				memset((PVOID)i, 0xcc, 0x1000);
				}_except(1)
				{
					continue;
				}
			}
			else
			{
				if (i > 0x1000000)
					break;
			}
		}

		KeDetachProcess();

		if (ObOpenObjectByPointer((PVOID)Eprocess, 0, NULL, 0, NULL, KernelMode, &handle) != STATUS_SUCCESS)
			return FALSE;
		ZwTerminateProcess((HANDLE)handle, STATUS_SUCCESS);
		ZwClose((HANDLE)handle);
		return TRUE;
	}
	return FALSE;
}

VOID RegistCallBack()
{
	NTSTATUS ntStatu = 0;
	ntStatu = PsSetLoadImageNotifyRoutine(LoadImageCallBack);
}

VOID LoadImageCallBack(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,               
	_In_ PIMAGE_INFO ImageInfo
)
{

	CHAR szTemp[1024] = { 0 };
	Unicode2Char(FullImageName, szTemp, 1024);
	ULONG len;
	PWCHAR position;
	UNICODE_STRING  unImgFileName;
	HANDLE hThread = NULL;

	if (ImageInfo)
	{



	}

}


NTSTATUS DenyLoadDriver(PVOID pImageBase)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMDL pMdl = NULL;
	PVOID pVoid = NULL;
	ULONG ulShellcodeLength = 16;
	UCHAR pShellcode[16] = { 0xB8, 0x22, 0x00, 0x00, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	PIMAGE_DOS_HEADER pDosHeader = pImageBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	PVOID pDriverEntry = (PVOID)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	pMdl = MmCreateMdl(NULL, pDriverEntry, ulShellcodeLength);
	MmBuildMdlForNonPagedPool(pMdl);
	pVoid = MmMapLockedPages(pMdl, KernelMode);
	RtlCopyMemory(pVoid, pShellcode, ulShellcodeLength);
	MmUnmapLockedPages(pVoid, pMdl);
	IoFreeMdl(pMdl);
	return status;
}



VOID ThreadProc(_In_ PVOID StartContext)
{
	PIMG_DATA pMyData = (PIMG_DATA)StartContext;
	LARGE_INTEGER liTime = { 0 };

	// ��ʱ 1 �� ��ֵ��ʾ���ʱ��
	liTime.QuadPart = -10 * 1000 * 1000;
	KeDelayExecutionThread(KernelMode, FALSE, &liTime);

	// ж��
	DenyLoadDll(pMyData->ProcessId, pMyData->pImageBase);

	ExFreePool(pMyData);
}



NTSTATUS DeleFile(UNICODE_STRING targetFile)
{
	
	OBJECT_ATTRIBUTES objectAttributes;
	NTSTATUS status;

	// ��ȡZwDeleteFile�����ĵ�ַ
	UNICODE_STRING functionName;
	RtlInitUnicodeString(&functionName, L"ZwDeleteFile");
	ZwDeleteFilePtr = (ZWDELETEFILE)MmGetSystemRoutineAddress(&functionName);

	if (ZwDeleteFilePtr == NULL) {
		// �޷���ȡZwDeleteFile�����ĵ�ַ����������ʧ��
		KdPrint(("Failed to get address of ZwDeleteFile\n"));
		return STATUS_UNSUCCESSFUL;
	}
	// ����Ҫɾ�����ļ�·��
	//RtlInitUnicodeString(&targetFile, L"\\DosDevices\\C:\\Path\\To\\File.txt");

	// ��ʼ��OBJECT_ATTRIBUTES�ṹ��
	InitializeObjectAttributes(&objectAttributes, &targetFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// ����ZwDeleteFile����ɾ���ļ�
	status = ZwDeleteFilePtr(&objectAttributes);

	if (NT_SUCCESS(status)) {
		KdPrint(("File deleted successfully\n"));
	}
	else {
		KdPrint(("Failed to delete file: 0x%X\n", status));
	}
}



VOID ProtectFile(const char* filePath)
{
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	UNICODE_STRING uniFilePath;

	// �� char* ת��Ϊ Unicode �ַ���
	RtlInitAnsiString(&uniFilePath, filePath);
	RtlAnsiStringToUnicodeString(&uniFilePath, &uniFilePath, TRUE);

	// ��ʼ�� OBJECT_ATTRIBUTES �ṹ��
	InitializeObjectAttributes(&objectAttributes, &uniFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// ���ļ�
	NTSTATUS status = ZwCreateFile(&hFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (NT_SUCCESS(status))
	{
		// �����ļ�
		FILE_BASIC_INFORMATION fileInfo;
		status = ZwQueryInformationFile(hFile, &ioStatusBlock, &fileInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
		if (NT_SUCCESS(status))
		{
			fileInfo.FileAttributes |= FILE_ATTRIBUTE_READONLY;
			status = ZwSetInformationFile(hFile, &ioStatusBlock, &fileInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
			if (NT_SUCCESS(status))
			{
				// �ļ������ɹ�
			}
		}

		// �ر��ļ����
		ZwClose(hFile);
	}

	// �ͷ� Unicode �ַ���
	RtlFreeUnicodeString(&uniFilePath);
}





NTSTATUS Unicode2Char(PUNICODE_STRING unicode, PCHAR pChar, ULONG uLenth)
{
	NTSTATUS status = STATUS_SUCCESS;
	ANSI_STRING strTemp;

	RtlZeroMemory(pChar, uLenth);
	RtlUnicodeStringToAnsiString(&strTemp, unicode, TRUE);
	if (uLenth > strTemp.Length)
	{
		RtlCopyMemory(pChar, strTemp.Buffer, strTemp.Length);
	}
	RtlFreeAnsiString(&strTemp);

	return status;
	
}


NTSTATUS DenyLoadDll(HANDLE ProcessId, PVOID pImageBase)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;

	status = PsLookupProcessByProcessId(ProcessId, &pEProcess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// ж��ģ��
	status = MmUnmapViewOfSection(pEProcess, pImageBase);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	return status;
}


VOID CreateProcessCallBack(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	if (CreateInfo)
	{
		for (size_t i = 0; i < FILE_NUM; i++)
		{
			
			if (wcsstr(CreateInfo->ImageFileName->Buffer, unBlackProcessName[i].Buffer) && 
				wcslen(unBlackProcessName[i].Buffer)>4)
			{
				DbgPrintEx(77, 0, "[db]�ɹ�����\n");
				CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
				break;
			}
		}
		
	}

}

UNICODE_STRING ConvertToUnicodeString(char* asciiString)
{
	ANSI_STRING ansiString;
	UNICODE_STRING unicodeString;

	RtlInitAnsiString(&ansiString, asciiString);
	RtlAnsiStringToUnicodeString(&unicodeString, &ansiString, TRUE);

	return unicodeString;
}



NTSTATUS unloadWpdFlt(PDRIVER_OBJECT pDriver)
{
	PDEVICE_OBJECT pDevice;
	PDEV_EXTENSION devExt;

	DbgPrint("DriverEntry Unloading...\n");

	pDevice = pDriver->DeviceObject;
	while (pDevice)
	{
		DeAttach(pDevice);
		pDevice = pDevice->NextDevice;
	}
}
NTSTATUS DeAttach(PDEVICE_OBJECT pdevice)
{
	PDEV_EXTENSION devExt;
	devExt = (PDEV_EXTENSION)pdevice->DeviceExtension;

	IoDetachDevice(devExt->TargeDevice);
	devExt->TargeDevice = NULL;
	IoDeleteDevice(pdevice);
	devExt->FilterDevice = NULL;

	return STATUS_SUCCESS;
}
NTSTATUS GetWindowsVersion(OUT PRTL_OSVERSIONINFOW pOsVersionInfo)
{
	if (pOsVersionInfo == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RTL_OSVERSIONINFOW osVersionInfo;
	RtlZeroMemory(&osVersionInfo, sizeof(RTL_OSVERSIONINFOW));
	osVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	NTSTATUS status = RtlGetVersion(&osVersionInfo);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// Copy the version information to the output parameter
	RtlCopyMemory(pOsVersionInfo, &osVersionInfo, sizeof(RTL_OSVERSIONINFOW));

	return STATUS_SUCCESS;
}
NTSTATUS GeneralDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	NTSTATUS status;

	DbgPrint("General Diapatch\n");

	PDEV_EXTENSION devExt = (PDEV_EXTENSION)pDevice->DeviceExtension;
	PDEVICE_OBJECT lowDevice = devExt->LowDevice;


	if (MmIsAddressValid(pIrp->AssociatedIrp.SystemBuffer))
	{
		RtlZeroMemory(pIrp->AssociatedIrp.SystemBuffer, 2);
	}

	IoSkipCurrentIrpStackLocation(pIrp);
	status = IoCallDriver(lowDevice, pIrp);

	return status;
}
NTSTATUS PowerDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	PDEV_EXTENSION devExt;
	devExt = (PDEV_EXTENSION)pDevice->DeviceExtension;

	PoStartNextPowerIrp(pIrp);
	IoSkipCurrentIrpStackLocation(pIrp);
	return PoCallDriver(devExt->TargeDevice, pIrp);
}
NTSTATUS PnPDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	PDEV_EXTENSION devExt;
	PIO_STACK_LOCATION stack;
	NTSTATUS status = STATUS_SUCCESS;

	devExt = (PDEV_EXTENSION)pDevice->DeviceExtension;
	stack = IoGetCurrentIrpStackLocation(pIrp);

	switch (stack->MinorFunction)
	{
	case IRP_MN_REMOVE_DEVICE:
		// ���Ȱ�������ȥ
		IoSkipCurrentIrpStackLocation(pIrp);
		IoCallDriver(devExt->LowDevice, pIrp);
		// Ȼ�����󶨡�
		IoDetachDevice(devExt->LowDevice);
		// ɾ�������Լ����ɵ������豸��
		IoDeleteDevice(pDevice);
		status = STATUS_SUCCESS;
		break;

	default:
		// �����������͵�IRP��ȫ����ֱ���·����ɡ� 
		IoSkipCurrentIrpStackLocation(pIrp);
		status = IoCallDriver(devExt->LowDevice, pIrp);
	}
	return status;
}
NTSTATUS DevExtInit(PDEV_EXTENSION devExt, PDEVICE_OBJECT filterDevice, PDEVICE_OBJECT targetDevice, PDEVICE_OBJECT lowDevice)
{
	memset(devExt, 0, sizeof(DEV_EXTENSION));
	devExt->FilterDevice = filterDevice;
	devExt->TargeDevice = targetDevice;
	devExt->LowDevice = lowDevice;
	devExt->Size = sizeof(DEV_EXTENSION);
	KeInitializeSpinLock(&devExt->IoRequestSpinLock);
	KeInitializeEvent(&devExt->IoInProgressEvent, NotificationEvent, FALSE);
	return STATUS_SUCCESS;
}
NTSTATUS AttachDevice(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPatch)
{
	UNICODE_STRING kbdName;

	if (osinfo.dwMajorVersion == 6)
	{
		RtlInitUnicodeString(&kbdName, L"\\Driver\\WUDFRd");
	}

	if (osinfo.dwMajorVersion == 10)
	{
		RtlInitUnicodeString(&kbdName, L"\\Driver\\WpdUpFltr");
	}

	NTSTATUS status = 0;
	PDEV_EXTENSION devExt;			// �����豸����չ�豸
	PDEVICE_OBJECT filterDevice;	// �����豸 
	PDEVICE_OBJECT targetDevice;		// Ŀ���豸�������豸��
	PDEVICE_OBJECT lowDevice;		// �ײ��豸����ĳһ���豸�ϼ�һ���豸ʱ��һ���Ǽӵ����豸�ϣ��������豸ջ��ջ����
	PDRIVER_OBJECT kbdDriver;		// ���ڽ��մ򿪵���������豸

	// ��ȡ���������Ķ��󣬱�����kbdDriver
	status = ObReferenceObjectByName(&kbdName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, &kbdDriver);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Open KeyBoard Driver Failed\n");
		return status;
	}
	else
	{
		// ������
		ObDereferenceObject(kbdDriver);
	}

	// ��ȡ���������豸���еĵ�һ���豸
	targetDevice = kbdDriver->DeviceObject;
	// ���������һ�����������̼����豸���е������豸
	while (targetDevice)
	{
		// ����һ�������豸
		status = IoCreateDevice(pDriver, sizeof(DEV_EXTENSION), NULL, targetDevice->DeviceType, targetDevice->Characteristics, FALSE, &filterDevice);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("Create New FilterDevice Failed\n");
			filterDevice = targetDevice = NULL;
			return status;
		}
		// �󶨣�lowDevice�ǰ�֮��õ�����һ���豸��
		lowDevice = IoAttachDeviceToDeviceStack(filterDevice, targetDevice);
		DbgPrint("tar:%p\n low:%p\n");
		if (!lowDevice)
		{
			DbgPrint("Attach Faided!\n");
			IoDeleteDevice(filterDevice);
			filterDevice = NULL;
			return status;
		}
		// ��ʼ���豸��չ
		devExt = (PDEV_EXTENSION)filterDevice->DeviceExtension;
		DevExtInit(devExt, filterDevice, targetDevice, lowDevice);

		filterDevice->DeviceType = lowDevice->DeviceType;
		filterDevice->Characteristics = lowDevice->Characteristics;
		filterDevice->StackSize = lowDevice->StackSize + 1;
		filterDevice->Flags |= lowDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
		// ������һ���豸
		targetDevice = targetDevice->NextDevice;
	}
	DbgPrint("Create And Attach Finshed...\n");
	return status;
}
NTSTATUS StartFltWpd(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPath)
{
	ULONG i;
	NTSTATUS status = STATUS_SUCCESS;

	GetWindowsVersion(&osinfo);

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriver->MajorFunction[i] = GeneralDispatch;		// ע��ͨ�õ�IRP�ַ�����
	}

	pDriver->MajorFunction[IRP_MJ_POWER] = PowerDispatch;	// ע���ԴIRP�ַ�����
	pDriver->MajorFunction[IRP_MJ_PNP] = PnPDispatch;		// ע�ἴ�弴��IRP�ַ�����

	AttachDevice(pDriver, RegPath);						// ���豸
}