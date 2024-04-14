#pragma once
#include <ntddk.h>
#include <ntddkbd.h>

#define WPDDEV_NAME L"\\Device\\wpdflt"
#define WPDSYM_NAME L"\\DosDevices\\wpdflt"

#define CTL_CODE_BASE 0x8000
#define CTL_CMD(i) CTL_CODE(FILE_DEVICE_UNKNOWN,CTL_CODE_BASE+i,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define  CTL_START_WPDFLT CTL_CMD(66)
#define  CTL_STOP_WPDFLT CTL_CMD(67)
/** 向前声明 */
NTKERNELAPI
UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
/*
*
启动过滤
StartFltWpd(pDriver, RegPath);
关闭过滤
unloadWpdFlt(pDriver);
*
*/
PDRIVER_OBJECT g_pdriver;
PUNICODE_STRING g_regpath;
INT g_FltFlag;

// 设备扩展结构
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
		// 首先把请求发下去
		IoSkipCurrentIrpStackLocation(pIrp);
		IoCallDriver(devExt->LowDevice, pIrp);
		// 然后解除绑定。
		IoDetachDevice(devExt->LowDevice);
		// 删除我们自己生成的虚拟设备。
		IoDeleteDevice(pDevice);
		status = STATUS_SUCCESS;
		break;

	default:
		// 对于其他类型的IRP，全部都直接下发即可。 
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


//映像模块回调
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
			AttachDevice(g_pdriver, g_regpath);						// 绑定设备

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
	PDEV_EXTENSION devExt;			// 过滤设备的扩展设备
	PDEVICE_OBJECT filterDevice;	// 过滤设备 
	PDEVICE_OBJECT targetDevice;		// 目标设备（键盘设备）
	PDEVICE_OBJECT lowDevice;		// 底层设备（向某一个设备上加一个设备时不一定是加到此设备上，而加在设备栈的栈顶）
	PDRIVER_OBJECT kbdDriver;		// 用于接收打开的物理键盘设备

	// 获取键盘驱动的对象，保存在kbdDriver
	status = ObReferenceObjectByName(&kbdName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, &kbdDriver);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("Open KeyBoard Driver Failed\n");
		return status;
	}
	else
	{
		// 解引用
		ObDereferenceObject(kbdDriver);
	}

	// 获取键盘驱动设备链中的第一个设备
	targetDevice = kbdDriver->DeviceObject;
	// 像链表操作一样，遍历键盘键盘设备链中的所有设备
	while (targetDevice)
	{
		// 创建一个过滤设备
		status = IoCreateDevice(pDriver, sizeof(DEV_EXTENSION), NULL, targetDevice->DeviceType, targetDevice->Characteristics, FALSE, &filterDevice);
		if (!NT_SUCCESS(status))
		{
			//DbgPrint("Create New FilterDevice Failed\n");
			filterDevice = targetDevice = NULL;
			return status;
		}
		// 绑定，lowDevice是绑定之后得到的下一个设备。
		lowDevice = IoAttachDeviceToDeviceStack(filterDevice, targetDevice);
		//DbgPrint("tar:%p\n low:%p\n");
		if (!lowDevice)
		{
			DbgPrint("Attach Faided!\n");
			IoDeleteDevice(filterDevice);
			filterDevice = NULL;
			return status;
		}
		// 初始化设备扩展
		devExt = (PDEV_EXTENSION)filterDevice->DeviceExtension;
		DevExtInit(devExt, filterDevice, targetDevice, lowDevice);

		filterDevice->DeviceType = lowDevice->DeviceType;
		filterDevice->Characteristics = lowDevice->Characteristics;
		filterDevice->StackSize = lowDevice->StackSize + 1;
		filterDevice->Flags |= lowDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
		// 遍历下一个设备
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
			pDriver->MajorFunction[i] = GeneralDispatch;		// 注册通用的IRP分发函数
		}

		
	}


	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlDispatch;


	pDriver->MajorFunction[IRP_MJ_POWER] = PowerDispatch;	// 注册电源IRP分发函数
	pDriver->MajorFunction[IRP_MJ_PNP] = PnPDispatch;		// 注册即插即用IRP分发函数


}

VOID Unload(PDRIVER_OBJECT pDriver)
{
	unloadWpdFlt(pDriver);
	//移除映像回调
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