#pragma once
#include <ntddk.h>
#include <ntddkbd.h>

#define WPDDEV_NAME L"\\Device\\wpdflt"
#define WPDSYM_NAME L"\\DosDevices\\wpdflt"

#define CTL_CODE_BASE 0x8000
#define CTL_CMD(i) CTL_CODE(FILE_DEVICE_UNKNOWN,CTL_CODE_BASE+i,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define  CTL_START_WPDFLT CTL_CMD(66)
#define  CTL_STOP_WPDFLT CTL_CMD(67)
/** ��ǰ���� */
NTKERNELAPI
UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
/*
*
��������
StartFltWpd(pDriver, RegPath);
�رչ���
unloadWpdFlt(pDriver);
*
*/
PDRIVER_OBJECT g_pdriver;
PUNICODE_STRING g_regpath;
INT g_FltFlag;

// �豸��չ�ṹ
typedef struct _Dev_exten
{
	ULONG Size;						// �ýṹ��С
	PDEVICE_OBJECT FilterDevice;	// �����豸����
	PDEVICE_OBJECT TargeDevice;		// ��һ�豸����
	PDEVICE_OBJECT LowDevice;		// ��ײ��豸����
	KSPIN_LOCK IoRequestSpinLock;	// ������
	KEVENT IoInProgressEvent;		// �¼�
	PIRP pIrp;						// IRP
} DEV_EXTENSION, * PDEV_EXTENSION;


// ����΢��δ������ObReferenceObjectByName()����
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

RTL_OSVERSIONINFOW osinfo;



NTSTATUS GetWindowsVersion(OUT PRTL_OSVERSIONINFOW pOsVersionInfo);
NTSTATUS DeAttach(PDEVICE_OBJECT pdevice);
NTSTATUS unloadWpdFlt(PDRIVER_OBJECT pDriver);
NTSTATUS GeneralDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS PowerDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS PnPDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS DevExtInit(PDEV_EXTENSION devExt, PDEVICE_OBJECT filterDevice, PDEVICE_OBJECT targetDevice, PDEVICE_OBJECT lowDevice);
NTSTATUS AttachDevice(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPatch);
NTSTATUS StartFltWpd(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPath);



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

	if (devExt==NULL)
	{
		return STATUS_SUCCESS;
	}

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

	PEPROCESS pEprocess = PsGetCurrentProcess();

	if (strstr(PsGetProcessImageFileName(pEprocess),"HPTS"))
	{
		pIrp->IoStatus.Information = 0;
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		ObDereferenceObject(pEprocess);
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	DbgPrint("General Diapatch\n");

	PDEV_EXTENSION devExt = (PDEV_EXTENSION)pDevice->DeviceExtension;
	PDEVICE_OBJECT lowDevice = devExt->LowDevice;


	if (MmIsAddressValid(pIrp->AssociatedIrp.SystemBuffer)&&g_FltFlag)
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


//ӳ��ģ��ص�
VOID LoadImageCallBack(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo
)
{
	if (ImageInfo && g_FltFlag)
	{
		if (!wcsstr(FullImageName, L"WpdUpFltr"))
		{
			AttachDevice(g_pdriver, g_regpath);						// ���豸

		}

	}
}


NTSTATUS IoControlDispatch(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG CtlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
	switch (CtlCode)
	{
	case CTL_START_WPDFLT:
	{
		g_FltFlag = 1;
		break;
	}
	case CTL_STOP_WPDFLT:
	{
		
		g_FltFlag = 0;
		unloadWpdFlt(g_pdriver);
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
		//DbgPrint("Open KeyBoard Driver Failed\n");
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
			//DbgPrint("Create New FilterDevice Failed\n");
			filterDevice = targetDevice = NULL;
			return status;
		}
		// �󶨣�lowDevice�ǰ�֮��õ�����һ���豸��
		lowDevice = IoAttachDeviceToDeviceStack(filterDevice, targetDevice);
		//DbgPrint("tar:%p\n low:%p\n");
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
	
	g_FltFlag = 0;

	GetWindowsVersion(&osinfo);

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		if (i!= IRP_MJ_DEVICE_CONTROL)
		{
			pDriver->MajorFunction[i] = GeneralDispatch;		// ע��ͨ�õ�IRP�ַ�����
		}

		
	}


	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlDispatch;


	pDriver->MajorFunction[IRP_MJ_POWER] = PowerDispatch;	// ע���ԴIRP�ַ�����
	pDriver->MajorFunction[IRP_MJ_PNP] = PnPDispatch;		// ע�ἴ�弴��IRP�ַ�����


}

VOID Unload(PDRIVER_OBJECT pDriver)
{
	unloadWpdFlt(pDriver);
	//�Ƴ�ӳ��ص�
	PsRemoveLoadImageNotifyRoutine(LoadImageCallBack);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriveObject, PUNICODE_STRING Regpath)
{

	NTSTATUS ntStatu = NULL;
	g_pdriver = pDriveObject;
	g_regpath = Regpath;







	PDEVICE_OBJECT pDevice = NULL;
	UNICODE_STRING uDeciceName = RTL_CONSTANT_STRING(WPDDEV_NAME);
	UNICODE_STRING uSyb_Name = RTL_CONSTANT_STRING(WPDSYM_NAME);

	ntStatu = IoCreateDevice(pDriveObject, 0, &uDeciceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevice);
	if (!NT_SUCCESS(ntStatu))
	{
		return STATUS_UNSUCCESSFUL;
		//DbgPrintEx(77, 0, "CreateDeviceFaild\n");
	}

	ntStatu = IoCreateSymbolicLink(&uSyb_Name, &uDeciceName);
	if (!NT_SUCCESS(ntStatu))
	{
		return STATUS_UNSUCCESSFUL;
		//DbgPrintEx(77, 0, "CreateSysbolinkFaild\n");
	}


	

	



	ntStatu = PsSetLoadImageNotifyRoutine(LoadImageCallBack);
	StartFltWpd(pDriveObject, Regpath);




	




	pDriveObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}