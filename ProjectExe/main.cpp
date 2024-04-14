#include "hook.hpp"
#include "tool.h"




NTSTATUS ProtectFunction(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
){
	HANDLE pid = ClientId->UniqueProcess;

	for (int i = 0; i < PROCESS_NUM; i++)
	{
		PVOID address = PidArray;
		if (pid == PidArray[i] && pid!=0)
		{
			return STATUS_ACCESS_DENIED;
		}
	}

	return NtOpen(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId
	);
}

void __fastcall call_back(unsigned long ssdt_index, void** ssdt_address)
{
	UNREFERENCED_PARAMETER(ssdt_index);
	if (*ssdt_address == ADDR) *ssdt_address = ProtectFunction;
}


VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);
	UNICODE_STRING uSyb_Name = RTL_CONSTANT_STRING(SYMBOLIC_NAME);
	IoDeleteDevice(pDriver->DeviceObject);
	IoDeleteSymbolicLink(&uSyb_Name);
	DbgPrint("Ð¶ÔØ³É¹¦");
	PsRemoveLoadImageNotifyRoutine(LoadImageCallBack);
	PsSetCreateProcessNotifyRoutineEx(CreateProcessCallBack, TRUE);
	EnbleDebugThread();
	k_hook::stop();
	UnloadFileFilter();
}

EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriver,
	PUNICODE_STRING registe)
{
	UNREFERENCED_PARAMETER(registe);
	InitDriver(pDriver);
	pDriver->DriverUnload = DriverUnload;
	UNICODE_STRING unOpenProcessName = RTL_CONSTANT_STRING(L"NtOpenProcess");
	ADDR = MmGetSystemRoutineAddress(&unOpenProcessName);
	NtOpen = (MyNtOpenProcess)ADDR;
	DbgPrintEx(77, 0, "ADDR:%p\n", ADDR);
	return k_hook::initialize(call_back) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}










