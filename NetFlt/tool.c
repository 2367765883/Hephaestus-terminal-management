#include "tool.h"



// ������������
HANDLE g_hEngine = 0;

// �����������е�callout������ʱ��ʶ��
ULONG32 g_AleConnectCalloutId = 0;

// ������������ʱ��ʶ��
ULONG64 g_AleConnectFilterId = 0;

// ָ��ΨһUUIDֵ(ֻҪ����ͻ����,���ݿ�����)
GUID GUID_ALE_AUTH_CONNECT_CALLOUT_V4 = { 0x69129683, 0x7d3e, 0x499a, 0xa0, 0x12, 0x55, 0xe0, 0xd8, 0x5f, 0x34, 0x8b };

CHAR g_IPBlackList[IPS_NUM][IPS_NUM] = { 0 };

KSPIN_LOCK g_IpListSpinLock = {0};

NTSTATUS DispatchControl(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	PVOID pBuff = pIrp->AssociatedIrp.SystemBuffer;
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG CtlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
	switch (CtlCode)
	{
	case CTL_BLOCK:
	{
		KIRQL tmpIrql = { 0 };

		KeAcquireSpinLock(&g_IpListSpinLock, &tmpIrql);

		for (size_t i = 0; i < IPS_NUM; i++)
		{
			if (!strcmp(g_IPBlackList[i], pBuff))
			{
				break;
			}
			if (!strcmp(g_IPBlackList[i], ""))
			{
				RtlCopyMemory(g_IPBlackList[i], pBuff, pStack->Parameters.DeviceIoControl.InputBufferLength);
				break;
			}
		}

		KeReleaseSpinLock(&g_IpListSpinLock, tmpIrql);

		break;
	}
	case CTL_REMOVEBLOCK:
	{
		KIRQL tmpIrql = { 0 };

		KeAcquireSpinLock(&g_IpListSpinLock, &tmpIrql);

		for (size_t i = 0; i < IPS_NUM; i++)
		{
			if (!strcmp(g_IPBlackList[i], pBuff))
			{
				RtlZeroMemory(g_IPBlackList[i], pStack->Parameters.DeviceIoControl.InputBufferLength);
			}
		}

		KeReleaseSpinLock(&g_IpListSpinLock, tmpIrql);

		break;
	}
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
	}
}





// Э���ж�
NTSTATUS ProtocalIdToName(UINT16 protocalId, PCHAR lpszProtocalName)
{
	NTSTATUS status = STATUS_SUCCESS;

	switch (protocalId)
	{
	case 1:
	{
		// ICMP
		RtlCopyMemory(lpszProtocalName, "ICMP", 5);
		break;
	}
	case 2:
	{
		// IGMP
		RtlCopyMemory(lpszProtocalName, "IGMP", 5);
		break;
	}
	case 6:
	{
		// TCP
		RtlCopyMemory(lpszProtocalName, "TCP", 4);
		break;
	}
	case 17:
	{
		// UDP
		RtlCopyMemory(lpszProtocalName, "UDP", 4);
		break;
	}
	case 27:
	{
		// RDP
		RtlCopyMemory(lpszProtocalName, "RDP", 6);
		break;
	}
	default:
	{
		// UNKNOW
		RtlCopyMemory(lpszProtocalName, "UNKNOWN", 8);
		break;
	}
	}

	return status;
}



// ����WFP
NTSTATUS WfpLoad(PDEVICE_OBJECT pDevObj)
{
	NTSTATUS status = STATUS_SUCCESS;

	// ע��Callout�����ù��˵�
	// classifyFn, notifyFn, flowDeleteFn ע�������ص�����,һ����ǰ�ص�,�����º�ص�
	status = RegisterCalloutForLayer(pDevObj, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &GUID_ALE_AUTH_CONNECT_CALLOUT_V4,
		(FWPS_CALLOUT_CLASSIFY_FN3)classifyFn, (FWPS_CALLOUT_CLASSIFY_FN3)notifyFn, flowDeleteFn, &g_AleConnectCalloutId, &g_AleConnectFilterId, &g_hEngine);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ע��ص�ʧ�� \n");
		return status;
	}

	return status;
}



// ж��WFP
NTSTATUS WfpUnload()
{
	if (NULL != g_hEngine)
	{
		// ɾ��FilterId
		FwpmFilterDeleteById(g_hEngine, g_AleConnectFilterId);
		// ɾ��CalloutId
		FwpmCalloutDeleteById(g_hEngine, g_AleConnectCalloutId);
		// ���Filter
		g_AleConnectFilterId = 0;
		// ��ע��CalloutId
		FwpsCalloutUnregisterById(g_AleConnectCalloutId);
		// ���CalloutId
		g_AleConnectCalloutId = 0;
		// �ر�����
		FwpmEngineClose(g_hEngine);
		g_hEngine = NULL;
	}

	return STATUS_SUCCESS;
}


// ע��Callout�����ù��˵�
NTSTATUS RegisterCalloutForLayer(IN PDEVICE_OBJECT pDevObj, IN const GUID* layerKey, IN const GUID* calloutKey, IN FWPS_CALLOUT_CLASSIFY_FN classifyFn, IN FWPS_CALLOUT_NOTIFY_FN notifyFn, IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn, OUT ULONG32* calloutId, OUT ULONG64* filterId, OUT HANDLE* engine)
{
	NTSTATUS status = STATUS_SUCCESS;

	// ע��Callout
	status = RegisterCallout(pDevObj, calloutKey, classifyFn, notifyFn, flowDeleteNotifyFn, calloutId);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// ���ù��˵�
	status = SetFilter(layerKey, calloutKey, filterId, engine);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return status;
}






// ע��Callout
NTSTATUS RegisterCallout(PDEVICE_OBJECT pDevObj, IN const GUID* calloutKey, IN FWPS_CALLOUT_CLASSIFY_FN classifyFn, IN FWPS_CALLOUT_NOTIFY_FN notifyFn, IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn, OUT ULONG32* calloutId)
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPS_CALLOUT sCallout = { 0 };

	// ����Callout
	sCallout.calloutKey = *calloutKey;
	sCallout.classifyFn = classifyFn;
	sCallout.flowDeleteFn = flowDeleteNotifyFn;
	sCallout.notifyFn = notifyFn;

	// ע��Callout
	status = FwpsCalloutRegister(pDevObj, &sCallout, calloutId);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ע��Calloutʧ��\n");
		return status;
	}

	return status;
}

// ���ù��˵�
NTSTATUS SetFilter(IN const GUID* layerKey, IN const GUID* calloutKey, OUT ULONG64* filterId, OUT HANDLE* engine)
{
	HANDLE hEngine = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SESSION session = { 0 };
	FWPM_FILTER mFilter = { 0 };
	FWPM_CALLOUT mCallout = { 0 };
	FWPM_DISPLAY_DATA mDispData = { 0 };

	// ����Session
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &hEngine);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// ��ʼ����
	status = FwpmTransactionBegin(hEngine, 0);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// ����Callout����
	mDispData.name = L"MY WFP ";
	mDispData.description = L"WORLD OF DEMON";
	mCallout.applicableLayer = *layerKey;
	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = mDispData;

	// ���Callout��Session��
	status = FwpmCalloutAdd(hEngine, &mCallout, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// ���ù���������
	mFilter.action.calloutKey = *calloutKey;
	mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	mFilter.displayData.name = L"skcontrol";
	mFilter.displayData.description = L"skcontrol";
	mFilter.layerKey = *layerKey;
	mFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	mFilter.weight.type = FWP_EMPTY;

	// ��ӹ�����
	status = FwpmFilterAdd(hEngine, &mFilter, NULL, filterId);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// �ύ����
	status = FwpmTransactionCommit(hEngine);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	*engine = hEngine;
	return status;
}




// Callout���� classifyFn ��ǰ�ص�����
VOID NTAPI classifyFn(
	_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER2* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
	// ���ݰ��ķ���,ȡֵ FWP_DIRECTION_INBOUND = 1 �� FWP_DIRECTION_OUTBOUND = 0
	WORD wDirection = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.int8;

	// ���屾����ַ�뱾���˿�
	ULONG ulLocalIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT16 uLocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;

	// ����Զ˵�ַ��Զ˶˿�
	ULONG ulRemoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 uRemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

	// ��ȡ��ǰ����IRQ
	KIRQL kCurrentIrql = KeGetCurrentIrql();

	// ��ȡ����ID
	ULONG64 processId = inMetaValues->processId;
	UCHAR szProcessPath[256] = { 0 };
	CHAR szProtocalName[256] = { 0 };
	RtlZeroMemory(szProcessPath, 256);

	// ��ȡ����·��
	for (ULONG i = 0; i < inMetaValues->processPath->size; i++)
	{
		// �����ǿ��ַ��洢��
		szProcessPath[i] = inMetaValues->processPath->data[i];
	}

	// ��ȡ��ǰЭ������
	ProtocalIdToName(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint16, szProtocalName);

	// ����Ĭ�Ϲ��� ��������
	classifyOut->actionType = FWP_ACTION_PERMIT;


	char szRemoteAddress[256] = { 0 };

	sprintf(szRemoteAddress, "%u.%u.%u.%u", (ulRemoteIp >> 24) & 0xFF, (ulRemoteIp >> 16) & 0xFF, (ulRemoteIp >> 8) & 0xFF, (ulRemoteIp) & 0xFF);

	
	

	


	// �������ж�
	KIRQL tmpIrql = { 0 };

	KeAcquireSpinLock(&g_IpListSpinLock, &tmpIrql);

	for (size_t i = 0; i < IPS_NUM; i++)
	{
		if (!strcmp(szRemoteAddress,g_IPBlackList[i]))
		{
			// ���þܾ����� �ܾ�����
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->rights = classifyOut->rights & (~FWPS_RIGHT_ACTION_WRITE);
			classifyOut->flags = classifyOut->flags | FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		}
	}

	KeReleaseSpinLock(&g_IpListSpinLock, tmpIrql);
}



// Callout���� notifyFn �º�ص�����
NTSTATUS NTAPI notifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER2* filter)
{
	NTSTATUS status = STATUS_SUCCESS;
	return status;
}



// Callout���� flowDeleteFn �º�ص�����
VOID NTAPI flowDeleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId, _In_ UINT64 flowContext)
{
	return;
}

// Ĭ����ǲ����
NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}



// �����豸
NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT pDevObj = NULL;
	UNICODE_STRING ustrDevName, ustrSymName;
	RtlInitUnicodeString(&ustrDevName, DEV_NAME);
	RtlInitUnicodeString(&ustrSymName, NETSYM_NAME);

	status = IoCreateDevice(pDriverObject, 0, &ustrDevName, FILE_DEVICE_NETWORK, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = IoCreateSymbolicLink(&ustrSymName, &ustrDevName);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	KeInitializeSpinLock(&g_IpListSpinLock);

	return status;
}


// ж������
VOID UnDriver(PDRIVER_OBJECT driver)
{
	// ɾ���ص������͹�����,�ر�����
	WfpUnload();

	UNICODE_STRING ustrSymName;
	RtlInitUnicodeString(&ustrSymName, NETSYM_NAME);
	IoDeleteSymbolicLink(&ustrSymName);
	if (driver->DeviceObject)
	{
		IoDeleteDevice(driver->DeviceObject);
	}
}