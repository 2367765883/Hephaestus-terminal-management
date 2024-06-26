#pragma once
#include "headers.h"
extern "C"
{
#include "ssdt.h"
}
namespace k_hook
{
	// 回调函数

	typedef void(__fastcall* fptr_call_back)(unsigned long ssdt_index, void** ssdt_address);

	// 初始化数据
	bool initialize(fptr_call_back fptr);

	// 开始拦截函数调用
	bool start();

	// 结束拦截函数调用
	bool stop();

	void MyHalpHvCounterQueryCounter();

	void keQueryPerformanceCounterHook(ULONG_PTR pStack);
}