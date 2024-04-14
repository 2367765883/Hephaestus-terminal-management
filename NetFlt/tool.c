#include "tool.h"



// 过滤器引擎句柄
HANDLE g_hEngine = 0;

// 过滤器引擎中的callout的运行时标识符
ULONG32 g_AleConnectCalloutId = 0;

// 过滤器的运行时标识符
ULONG64 g_AleConnectFilterId = 0;

// 指定唯一UUID值(只要不冲突即可,内容可随意)
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





// 协议判断
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



// 启动WFP
NTSTATUS WfpLoad(PDEVICE_OBJECT pDevObj)
{
	NTSTATUS status = STATUS_SUCCESS;

	// 注册Callout并设置过滤点
	// classifyFn, notifyFn, flowDeleteFn 注册三个回调函数,一个事前回调,两个事后回调
	status = RegisterCalloutForLayer(pDevObj, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &GUID_ALE_AUTH_CONNECT_CALLOUT_V4,
		(FWPS_CALLOUT_CLASSIFY_FN3)classifyFn, (FWPS_CALLOUT_CLASSIFY_FN3)notifyFn, flowDeleteFn, &g_AleConnectCalloutId, &g_AleConnectFilterId, &g_hEngine);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("注册回调失败 \n");
		return status;
	}

	return status;
}



// 卸载WFP
NTSTATUS WfpUnload()
{
	if (NULL != g_hEngine)
	{
		// 删除FilterId
		FwpmFilterDeleteById(g_hEngine, g_AleConnectFilterId);
		// 删除CalloutId
		FwpmCalloutDeleteById(g_hEngine, g_AleConnectCalloutId);
		// 清空Filter
		g_AleConnectFilterId = 0;
		// 反注册CalloutId
		FwpsCalloutUnregisterById(g_AleConnectCalloutId);
		// 清空CalloutId
		g_AleConnectCalloutId = 0;
		// 关闭引擎
		FwpmEngineClose(g_hEngine);
		g_hEngine = NULL;
	}

	return STATUS_SUCCESS;
}


// 注册Callout并设置过滤点
NTSTATUS RegisterCalloutForLayer(IN PDEVICE_OBJECT pDevObj, IN const GUID* layerKey, IN const GUID* calloutKey, IN FWPS_CALLOUT_CLASSIFY_FN classifyFn, IN FWPS_CALLOUT_NOTIFY_FN notifyFn, IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn, OUT ULONG32* calloutId, OUT ULONG64* filterId, OUT HANDLE* engine)
{
	NTSTATUS status = STATUS_SUCCESS;

	// 注册Callout
	status = RegisterCallout(pDevObj, calloutKey, classifyFn, notifyFn, flowDeleteNotifyFn, calloutId);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// 设置过滤点
	status = SetFilter(layerKey, calloutKey, filterId, engine);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return status;
}






// 注册Callout
NTSTATUS RegisterCallout(PDEVICE_OBJECT pDevObj, IN const GUID* calloutKey, IN FWPS_CALLOUT_CLASSIFY_FN classifyFn, IN FWPS_CALLOUT_NOTIFY_FN notifyFn, IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn, OUT ULONG32* calloutId)
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPS_CALLOUT sCallout = { 0 };

	// 设置Callout
	sCallout.calloutKey = *calloutKey;
	sCallout.classifyFn = classifyFn;
	sCallout.flowDeleteFn = flowDeleteNotifyFn;
	sCallout.notifyFn = notifyFn;

	// 注册Callout
	status = FwpsCalloutRegister(pDevObj, &sCallout, calloutId);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("注册Callout失败\n");
		return status;
	}

	return status;
}

// 设置过滤点
NTSTATUS SetFilter(IN const GUID* layerKey, IN const GUID* calloutKey, OUT ULONG64* filterId, OUT HANDLE* engine)
{
	HANDLE hEngine = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SESSION session = { 0 };
	FWPM_FILTER mFilter = { 0 };
	FWPM_CALLOUT mCallout = { 0 };
	FWPM_DISPLAY_DATA mDispData = { 0 };

	// 创建Session
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &hEngine);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// 开始事务
	status = FwpmTransactionBegin(hEngine, 0);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// 设置Callout参数
	mDispData.name = L"MY WFP ";
	mDispData.description = L"WORLD OF DEMON";
	mCallout.applicableLayer = *layerKey;
	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = mDispData;

	// 添加Callout到Session中
	status = FwpmCalloutAdd(hEngine, &mCallout, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// 设置过滤器参数
	mFilter.action.calloutKey = *calloutKey;
	mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	mFilter.displayData.name = L"skcontrol";
	mFilter.displayData.description = L"skcontrol";
	mFilter.layerKey = *layerKey;
	mFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	mFilter.weight.type = FWP_EMPTY;

	// 添加过滤器
	status = FwpmFilterAdd(hEngine, &mFilter, NULL, filterId);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// 提交事务
	status = FwpmTransactionCommit(hEngine);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	*engine = hEngine;
	return status;
}




// Callout函数 classifyFn 事前回调函数
VOID NTAPI classifyFn(
	_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER2* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
	// 数据包的方向,取值 FWP_DIRECTION_INBOUND = 1 或 FWP_DIRECTION_OUTBOUND = 0
	WORD wDirection = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.int8;

	// 定义本机地址与本机端口
	ULONG ulLocalIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT16 uLocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;

	// 定义对端地址与对端端口
	ULONG ulRemoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 uRemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

	// 获取当前进程IRQ
	KIRQL kCurrentIrql = KeGetCurrentIrql();

	// 获取进程ID
	ULONG64 processId = inMetaValues->processId;
	UCHAR szProcessPath[256] = { 0 };
	CHAR szProtocalName[256] = { 0 };
	RtlZeroMemory(szProcessPath, 256);

	// 获取进程路径
	for (ULONG i = 0; i < inMetaValues->processPath->size; i++)
	{
		// 里面是宽字符存储的
		szProcessPath[i] = inMetaValues->processPath->data[i];
	}

	// 获取当前协议类型
	ProtocalIdToName(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint16, szProtocalName);

	// 设置默认规则 允许连接
	classifyOut->actionType = FWP_ACTION_PERMIT;


	char szRemoteAddress[256] = { 0 };

	sprintf(szRemoteAddress, "%u.%u.%u.%u", (ulRemoteIp >> 24) & 0xFF, (ulRemoteIp >> 16) & 0xFF, (ulRemoteIp >> 8) & 0xFF, (ulRemoteIp) & 0xFF);

	
	

	


	// 黑名单判断
	KIRQL tmpIrql = { 0 };

	KeAcquireSpinLock(&g_IpListSpinLock, &tmpIrql);

	for (size_t i = 0; i < IPS_NUM; i++)
	{
		if (!strcmp(szRemoteAddress,g_IPBlackList[i]))
		{
			// 设置拒绝规则 拒绝连接
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->rights = classifyOut->rights & (~FWPS_RIGHT_ACTION_WRITE);
			classifyOut->flags = classifyOut->flags | FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		}
	}

	KeReleaseSpinLock(&g_IpListSpinLock, tmpIrql);
}



// Callout函数 notifyFn 事后回调函数
NTSTATUS NTAPI notifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER2* filter)
{
	NTSTATUS status = STATUS_SUCCESS;
	return status;
}



// Callout函数 flowDeleteFn 事后回调函数
VOID NTAPI flowDeleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId, _In_ UINT64 flowContext)
{
	return;
}

// 默认派遣函数
NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}



// 创建设备
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


// 卸载驱动
VOID UnDriver(PDRIVER_OBJECT driver)
{
	// 删除回调函数和过滤器,关闭引擎
	WfpUnload();

	UNICODE_STRING ustrSymName;
	RtlInitUnicodeString(&ustrSymName, NETSYM_NAME);
	IoDeleteSymbolicLink(&ustrSymName);
	if (driver->DeviceObject)
	{
		IoDeleteDevice(driver->DeviceObject);
	}
}