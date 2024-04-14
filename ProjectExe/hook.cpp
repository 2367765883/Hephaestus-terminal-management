#include "hook.hpp"
#include "utils.hpp"

#pragma warning(disable : 4201)
BOOLEAN IsThread = TRUE;

/* ΢��ٷ��ĵ�����
*   https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header*/

extern "C" {
	uintptr_t Original_HalpHvCounterQueryCounter = 0;
	uintptr_t MyHalpHvCounterQueryCounterAddr = (uintptr_t)k_hook::keQueryPerformanceCounterHook;
	uintptr_t circularKernelContextLogger;
	void checkLogger();
}



typedef struct _WNODE_HEADER
{
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct {
			ULONG Version;
			ULONG Linkage;
		};
	};
	union {
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	};
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;

/* ΢���ĵ�����
*   https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties*/
typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER Wnode;
	ULONG BufferSize;
	ULONG MinimumBuffers;
	ULONG MaximumBuffers;
	ULONG MaximumFileSize;
	ULONG LogFileMode;
	ULONG FlushTimer;
	ULONG EnableFlags;
	union {
		LONG AgeLimit;
		LONG FlushThreshold;
	} DUMMYUNIONNAME;
	ULONG NumberOfBuffers;
	ULONG FreeBuffers;
	ULONG EventsLost;
	ULONG BuffersWritten;
	ULONG LogBuffersLost;
	ULONG RealTimeBuffersLost;
	HANDLE LoggerThreadId;
	ULONG LogFileNameOffset;
	ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

/* ��ṹ�Ǵ������������ */
typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64 Unknown[3];
	UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

// ��������
typedef enum _trace_type
{
	start_trace = 1,
	stop_trace = 2,
	query_trace = 3,
	syscall_trace = 4,
	flush_trace = 5
}trace_type;

namespace k_hook
{

	//__int64 __fastcall HalpTimerQueryHostPerformanceCounter(_QWORD *a1)


	// ���ֵ�ǹ̶������
	GUID g_ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

	EXTERN_C
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwTraceControl(
			_In_ ULONG FunctionCode,
			_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
			_In_ ULONG InBufferLen,
			_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
			_In_ ULONG OutBufferLen,
			_Out_ PULONG ReturnLength
		);



	fptr_call_back g_fptr = nullptr;
	unsigned long g_build_number = 0;

	void* g_EtwpDebuggerData = nullptr;
	void* g_CkclWmiLoggerContext = nullptr;
	void* g_syscall_table = nullptr;

	void** g_EtwpDebuggerDataSilo = nullptr;
	void** g_GetCpuClock = nullptr;

	unsigned long long h_original_GetCpuClock = 0;
	unsigned long long g_HvlpReferenceTscPage = 0;
	unsigned long long g_HvlGetQpcBias = 0;
	unsigned long long h_original_cmpcall = 0;
	unsigned long long g_HalpPerformanceCounter = 0;
	unsigned long long g_HalpTimerQueryHostPerformanceCounterAddr = 0;

	typedef __int64 (*fptr_HvlGetQpcBias)();
	fptr_HvlGetQpcBias g_original_HvlGetQpcBias = nullptr;

	typedef __int64(__fastcall* HalpTimerQueryHostPerformanceCounter)(uintptr_t a1);
	HalpTimerQueryHostPerformanceCounter Original_HalpTimerQueryHostPerformanceCounter = nullptr;

	// �޸ĸ�������
	NTSTATUS modify_trace_settings(trace_type type)
	{
		const unsigned long tag = 'VMON';

		// ����ṹ��ռ�
		CKCL_TRACE_PROPERTIES* property = (CKCL_TRACE_PROPERTIES*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, tag);
		if (!property)
		{
			DbgPrintEx(0, 0, "[%s] allocate ckcl trace propertice struct fail \n", __FUNCTION__);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		// ���뱣�����ƵĿռ�
		wchar_t* provider_name = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(wchar_t), tag);
		if (!provider_name)
		{
			DbgPrintEx(0, 0, "[%s] allocate provider name fail \n", __FUNCTION__);
			ExFreePoolWithTag(property, tag);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		// ����ڴ�
		RtlZeroMemory(property, PAGE_SIZE);
		RtlZeroMemory(provider_name, 256 * sizeof(wchar_t));

		// ���Ƹ�ֵ
		RtlCopyMemory(provider_name, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
		RtlInitUnicodeString(&property->ProviderName, (const wchar_t*)provider_name);

		// �ṹ�����
		property->Wnode.BufferSize = PAGE_SIZE;
		property->Wnode.Flags = 0x00020000;
		property->Wnode.Guid = g_ckcl_session_guid;
		property->Wnode.ClientContext = 3;
		property->BufferSize = sizeof(unsigned long);
		property->MinimumBuffers = 2;
		property->MaximumBuffers = 2;
		property->LogFileMode = 0x00000400;

		// ִ�в���
		unsigned long length = 0;
		if (type == trace_type::syscall_trace) property->EnableFlags = 0x00000080;
		NTSTATUS status = ZwTraceControl(type, property, PAGE_SIZE, property, PAGE_SIZE, &length);

		// �ͷ��ڴ�ռ�
		ExFreePoolWithTag(provider_name, tag);
		ExFreePoolWithTag(property, tag);

		return status;
	}

	// ���ǵ��滻����,��Ե��Ǵ�Win7��Win10 1909��ϵͳ
	unsigned long long self_get_cpu_clock()
	{
		// �Ź��ں�ģʽ�ĵ���
		if (ExGetPreviousMode() == KernelMode) return __rdtsc();

		// �õ���ǰ�߳�
		PKTHREAD current_thread = (PKTHREAD)__readgsqword(0x188);

		// ��ͬ�汾��ͬƫ��
		unsigned int call_index = 0;
		if (g_build_number <= 7601) call_index = *(unsigned int*)((unsigned long long)current_thread + 0x1f8);
		else call_index = *(unsigned int*)((unsigned long long)current_thread + 0x80);

		// �õ���ǰջ�׺�ջ��
		void** stack_max = (void**)__readgsqword(0x1a8);
		void** stack_frame = (void**)_AddressOfReturnAddress();

		// ��ʼ���ҵ�ǰջ�е�ssdt����
		for (void** stack_current = stack_max; stack_current > stack_frame; --stack_current)
		{
			/* ջ��ssdt��������,�ֱ���
			*   mov [rsp+48h+var_20], 501802h
			*   mov r9d, 0F33h
			*/
#define INFINITYHOOK_MAGIC_1 ((unsigned long)0x501802)
#define INFINITYHOOK_MAGIC_2 ((unsigned short)0xF33)

			// ��һ������ֵ���
			unsigned long* l_value = (unsigned long*)stack_current;
			if (!MmIsAddressValid((PVOID)l_value))break;
			if (*l_value != INFINITYHOOK_MAGIC_1) continue;

			// ����Ϊʲô��?���Ѱ�ҵڶ�������ֵ��
			--stack_current;

			// �ڶ�������ֵ���
			unsigned short* s_value = (unsigned short*)stack_current;
			if (!MmIsAddressValid((PVOID)s_value))break;
			if (*s_value != INFINITYHOOK_MAGIC_2) continue;

			// ����ֵƥ��ɹ�,�ٵ���������
			for (; stack_current < stack_max; ++stack_current)
			{
				// ����Ƿ���ssdt����
				unsigned long long* ull_value = (unsigned long long*)stack_current;
				if (!MmIsAddressValid((PVOID)ull_value))break;

				if (!(PAGE_ALIGN(*ull_value) >= g_syscall_table && PAGE_ALIGN(*ull_value) < (void*)((unsigned long long)g_syscall_table + (PAGE_SIZE * 2)))) continue;

				// �����Ѿ�ȷ����ssdt����������
				// �������ҵ�KiSystemServiceExit
				void** system_call_function = &stack_current[9];

				// ���ûص�����
				if (g_fptr) g_fptr(call_index, system_call_function);

				// ����ѭ��
				break;
			}

			// ����ѭ��
			break;
		}

		// ����ԭ����
		return __rdtsc();
	}



	void keQueryPerformanceCounterHook(ULONG_PTR pStack)
	{
		if (ExGetPreviousMode() == KernelMode) return;
		for (size_t i = 0; i < 30; i++)
		{
			uintptr_t Address = pStack + i * 8;
			//������ô�rip���±���30��
			if (!MmIsAddressValid((PVOID)Address))break;
			uintptr_t t = *(uintptr_t*)Address;
			if (t == circularKernelContextLogger)
			{
				self_get_cpu_clock();
				break;
			}
		}
	}
	bool initialize(fptr_call_back fptr)
	{
		// �ص�����ָ����
		if (!fptr) return false;
		//DbgPrintEx(0, 0, "[%s] call back ptr is 0x%p \n", __FUNCTION__, fptr);
		g_fptr = fptr;

		// ��ȡϵͳ�汾��
		g_build_number = k_utils::get_system_build_number();
		if (!g_build_number) return false;
		//DbgPrintEx(0, 0, "[%s] build number is %ld \n", __FUNCTION__, g_build_number);

		// ��ȡϵͳ��ַ
		unsigned long long ntoskrnl = k_utils::get_module_address("ntoskrnl.exe", nullptr);
		if (!ntoskrnl) return false;
		//DbgPrintEx(0, 0, "[%s] ntoskrnl address is 0x%llX \n", __FUNCTION__, ntoskrnl);

		// ���ﲻͬϵͳ��ͬλ��
		unsigned long long EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
		if (!EtwpDebuggerData) EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".data");
		if (!EtwpDebuggerData) EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".rdata");
		if (!EtwpDebuggerData) return false;
		//DbgPrintEx(0, 0, "[%s] etwp debugger data is 0x%llX \n", __FUNCTION__, EtwpDebuggerData);
		g_EtwpDebuggerData = (void*)EtwpDebuggerData;

		// ������ʱ��֪����ô��λ,ƫ��0x10��ȫ��ϵͳ��һ��
		g_EtwpDebuggerDataSilo = *(void***)((unsigned long long)g_EtwpDebuggerData + 0x10);
		if (!g_EtwpDebuggerDataSilo) return false;
		//DbgPrintEx(0, 0, "[%s] etwp debugger data silo is 0x%p \n", __FUNCTION__, g_EtwpDebuggerDataSilo);

		// ����Ҳ��֪����ô��λ,ƫ��0x2��ȫ��ϵͳ��Ŷһ��
		g_CkclWmiLoggerContext = g_EtwpDebuggerDataSilo[0x2];
		circularKernelContextLogger = (uintptr_t)g_CkclWmiLoggerContext;
		if (!g_CkclWmiLoggerContext) return false;
		//DbgPrintEx(0, 0, "[%s] ckcl wmi logger context is 0x%p \n", __FUNCTION__, g_CkclWmiLoggerContext);


		if (g_build_number <= 7601 || g_build_number >= 22000) g_GetCpuClock = (void**)((unsigned long long)g_CkclWmiLoggerContext + 0x18); // Win7�汾�Լ�����, Win11Ҳ��
		else g_GetCpuClock = (void**)((unsigned long long)g_CkclWmiLoggerContext + 0x28); // Win8 -> Win10ȫϵͳ
		if (!MmIsAddressValid(g_GetCpuClock)) return false;

		// �õ�ssdtָ��
		g_syscall_table = PAGE_ALIGN(k_utils::get_syscall_entry(ntoskrnl));
		if (!g_syscall_table) return false;
		//DbgPrintEx(0, 0, "[%s] syscall table is 0x%p \n", __FUNCTION__, g_syscall_table);

		if (g_build_number > 18363)
		{
			// 48 8B 05 ? ? ? ?  48 8B F9 48 85 C0 74 ? 83 B8 E4 00 00 00 
			long long g_HalpPerformanceCounterAddr = 0;
			g_HalpPerformanceCounterAddr = k_utils::find_pattern_image(ntoskrnl,
				"\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\xf9\x48\x85\xc0\x74\x00\x83\xb8\xe4\x00\x00\x00",
				"xxx????xxxxxxx?xxxxxx");
			g_HalpPerformanceCounter = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(g_HalpPerformanceCounterAddr) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(g_HalpPerformanceCounterAddr) + 3));
			if (!g_HalpPerformanceCounter)
			{
				DbgPrintEx(0, 0, "[%s] g_HalpPerformanceCounter fail! \n", __FUNCTION__);
				return false;
			}
			g_HalpPerformanceCounter = *(uintptr_t*)g_HalpPerformanceCounter;
			if (!g_HalpPerformanceCounter)
			{
				DbgPrintEx(0, 0, "[%s] HalpPerformanceCounter fail! \n", __FUNCTION__);
				return false;
			}
			//DbgPrintEx(0, 0, "[%s] g_HalpPerformanceCounter is 0x%p \n", __FUNCTION__, g_HalpPerformanceCounter);

			/*
			* EtwpGetLoggerTimeStamp
			* keQueryPerformanceCounter
			*
			nt!KeQueryPerformanceCounter+0x12:
			fffff800`05efbed2 488b3dcf7e9500  mov     rdi,qword ptr [nt!HalpPerformanceCounter (fffff800`06853da8)]
			nt!KeQueryPerformanceCounter+0xcc:
			fffff800`05efbf8c 488b4770        mov     rax,qword ptr [rdi+70h]
			nt!KeQueryPerformanceCounter+0xd0:
			fffff800`05efbf90 e8bbbd1000      call    nt!guard_dispatch_icall (fffff800`06007d50)
			nt!guard_dispatch_icall+0x71:
			fffff800`06007dc1 ffe0            jmp     rax


			* HalpPerformanceCounter
			*/
		}

		return true;
	}

	bool start()
	{
		if (!g_fptr) return false;

		if (!NT_SUCCESS(modify_trace_settings(syscall_trace)))
		{
			// �޷�����CKCL
			if (!NT_SUCCESS(modify_trace_settings(start_trace)))
			{
				DbgPrintEx(0, 0, "[%s] start ckcl fail \n", __FUNCTION__);
				return false;
			}

			// �ٴγ��Թҹ�
			if (!NT_SUCCESS(modify_trace_settings(syscall_trace)))
			{
				DbgPrintEx(0, 0, "[%s] syscall ckcl fail \n", __FUNCTION__);
				return false;
			}
		}

		// ��Чָ��
		if (!MmIsAddressValid(g_GetCpuClock))
		{
			DbgPrintEx(0, 0, "[%s] get cpu clock vaild \n", __FUNCTION__);
			return false;
		}

		if (g_build_number <= 18363)
		{
			*g_GetCpuClock = self_get_cpu_clock;
		}
		else
		{
			h_original_GetCpuClock = (unsigned long long)(*g_GetCpuClock);
			*g_GetCpuClock = (void*)1;
			Original_HalpHvCounterQueryCounter = *(unsigned long long*)(g_HalpPerformanceCounter + 0x70);
			*(unsigned  long long*)(g_HalpPerformanceCounter + 0x70) = (unsigned  long long)checkLogger;
		}

		return true;
	}

	bool stop()
	{
		bool result = NT_SUCCESS(modify_trace_settings(stop_trace)) && NT_SUCCESS(modify_trace_settings(start_trace));
		if (g_build_number > 18363)
		{
			*(unsigned  long long*)(g_HalpPerformanceCounter + 0x70) = (unsigned  long long)Original_HalpHvCounterQueryCounter;
			*g_GetCpuClock = (void*)h_original_GetCpuClock;
		}

		return result;
	}
}
