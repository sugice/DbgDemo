#include "stdafx.h"
#include "TfBp.h"


CTfBp::CTfBp()
{
}


CTfBp::~CTfBp()
{
}

//单步走（设置TF断点）
void CTfBp::UserCommandStepInto(DWORD dwThreadId) {
	// 设置单步
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext(hThread, &ct);
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	pElg->TF = 1;
	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
}