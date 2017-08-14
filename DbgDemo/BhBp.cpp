#include "stdafx.h"
#include "BhBp.h"
#include "MyType.h"

CBhBp::CBhBp()
{
}


CBhBp::~CBhBp()
{
}

//************************************
// Method:    SetBhExecBreakPoint
// FullName:  CBhBp::SetBhExecBreakPoint
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: DWORD dwThreadId
// Parameter: DWORD dwAddr
// Function:  设置硬件执行断点
//************************************
BOOL CBhBp::SetBhExecBreakPoint(DWORD dwThreadId, DWORD dwAddr)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dwThreadId);
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);//获取线程环境快
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0==0)//L0没有被使用
	{
		ct.Dr0 = dwAddr;//在Dr0寄存器中写入中断地址
		pDr7->RW0 = 0;//执行断点
		pDr7->LEN0 = 0;//（1字节长度）
		pDr7->L0 = 1;//启用该断点
	}
	else if (pDr7->L1==0)
	{
		ct.Dr1 = dwAddr;
		pDr7->RW1 = 0;
		pDr7->LEN1 = 0;
		pDr7->L0 = 1;
	}
	else if (pDr7->L2 == 0)
	{
		ct.Dr2 = dwAddr;
		pDr7->RW2 = 0;
		pDr7->LEN2 = 0;
		pDr7->L0 = 1;
	}
	else if (pDr7->L3 == 0)
	{
		ct.Dr3 = dwAddr;
		pDr7->RW3 = 0;
		pDr7->LEN3 = 0;
		pDr7->L0 = 1;
	}
	else
	{
		return FALSE;
	}
	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
	return TRUE;
}

BOOL CBhBp::SetBhRwBreakPoint(DWORD dwThreadId, DWORD dwAddr, DWORD dwType, DWORD dwLen)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dwThreadId);
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);//获取线程环境块
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;

	//对地址和长度进行对齐处理（向上取整）
	if (dwLen==1)//两字节的长度对齐
	{
		dwAddr = dwAddr - dwAddr % 2;
	}
	else if (dwLen == 3)
	{
		dwAddr = dwAddr - dwAddr % 4;
	}
	else if (dwLen > 3)
	{
		return FALSE;
	}
	//判断哪些寄存器没有被使用
	if (pDr7->L0 == 0)//L0没有被使用
	{
		ct.Dr0 = dwAddr;//在Dr0寄存器中写入中断地址
		pDr7->RW0 = dwType;//执行断点
		pDr7->LEN0 = dwLen;//（1字节长度）
	}
	else if (pDr7->L1 == 0)
	{
		ct.Dr1 = dwAddr;
		pDr7->RW1 = dwType;
		pDr7->LEN1 = dwLen;
	}
	else if (pDr7->L2 == 0)
	{
		ct.Dr2 = dwAddr;
		pDr7->RW2 = dwType;
		pDr7->LEN2 = dwLen;
	}
	else if (pDr7->L3 == 0)
	{
		ct.Dr3 = dwAddr;
		pDr7->RW3 = dwType;
		pDr7->LEN3 = dwLen;
	}
	else
	{
		return FALSE;
	}
	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
	return TRUE;
}

VOID CBhBp::ReSetAllBhRwBreakPoint(DWORD dwThreadId)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dwThreadId);
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);//获取线程环境块
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	//判断Dr0-Dr3这四个寄存器内有没有值
	if (ct.Dr0)
	{
		pDr7->L0 = 1;//启用该断点
		SetThreadContext(hThread, &ct);
	}
	if (ct.Dr1)
	{
		pDr7->L1 = 1;//启用该断点
		SetThreadContext(hThread, &ct);
	}
	if (ct.Dr2)
	{
		pDr7->L2 = 1;//启用该断点
		SetThreadContext(hThread, &ct);
	}
	if (ct.Dr3)
	{
		pDr7->L3 = 1;//启用该断点
		SetThreadContext(hThread, &ct);
	}
}

BOOL CBhBp::CheckDr6ForBhRwBreakPoint(DWORD dwThreadId)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dwThreadId);
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);//获取线程环境块
	DBG_REG6* pDr6 = (DBG_REG6*)&ct.Dr6;
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	//检查DR6中的B0-B3位
	if (pDr6->B0)
	{
		pDr7->L0 = 0;
		SetThreadContext(hThread, &ct);
		return TRUE;
	}
	if (pDr6->B1)
	{
		pDr7->L1 = 0;
		SetThreadContext(hThread, &ct);
		return TRUE;
	}
	if (pDr6->B2)
	{
		pDr7->L2 = 0;
		SetThreadContext(hThread, &ct);
		return TRUE;
	}
	if (pDr6->B3)
	{
		pDr7->L3 = 0;
		SetThreadContext(hThread, &ct);
		return TRUE;
	}
	return FALSE;
}
