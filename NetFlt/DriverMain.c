#include "tool.h"


NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	Driver->DriverUnload = UnDriver;

	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		Driver->MajorFunction[i] = DriverDefaultHandle;
	}

	CreateDevice(Driver);
	WfpLoad(Driver->DeviceObject);

	Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;
	Driver->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}
