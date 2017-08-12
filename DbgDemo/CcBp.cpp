#include "stdafx.h"
#include "CcBp.h"




CCcBp::CCcBp()
{
}


CCcBp::~CCcBp()
{
}



//************************************
// Method:    SetBsBreakPoint
// FullName:  CCcBp::SetBsBreakPoint
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: DWORD dwAddr 断点地址
// Parameter: HANDLE hProcess 目标进程
// Function:  设置软件断点
//************************************
BOOL CCcBp::SetBsBreakPoint(DWORD dwAddr, HANDLE hProcess)
{
	//读取进程内存，保存一个字节的数据
	DWORD dwSize = 0;
	if (!ReadProcessMemory(hProcess,&dwAddr,&m_oldByte,1,&dwSize))
		return FALSE;
	//写入一个字节，\xcc就是int3指令的机器码
	BYTE cc = '\xcc';
	if (!WriteProcessMemory(hProcess, &dwAddr, &cc, 1, &dwSize))
		return FALSE;
	return TRUE;
}

//************************************
// Method:    RemoveBsBreakPoint
// FullName:  CCcBp::RemoveBsBreakPoint
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: DWORD dwAddr 断点地址
// Parameter: HANDLE hProcess 目标进程
// Function:  取消软件断点
//************************************
BOOL CCcBp::RemoveBsBreakPoint(DWORD dwAddr, HANDLE hProcess)
{
	DWORD dwSize = 0;
	return WriteProcessMemory(hProcess, &dwAddr, &m_oldByte, 1, &dwSize);
}


//************************************
// Method:    EipSubOne
// FullName:  CCcBp::EipSubOne
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: DWORD dwThreadId
// Function:  将被调试线程EIP减一
//************************************
BOOL CCcBp::EipSubOne(DWORD dwThreadId)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext(hThread, &ct);
	ct.Eip--;
	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
	return TRUE;
}