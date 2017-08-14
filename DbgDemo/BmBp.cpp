#include "stdafx.h"
#include "BmBp.h"


CBmBp::CBmBp()
{
}


CBmBp::~CBmBp()
{
}

BOOL CBmBp::SetBmBreakPoint(DWORD dwAddr, HANDLE hProcess)
{
	m_dwAddr = dwAddr;//保存内存断点地址
	//修改内存分页属性，改为没有任何访问权限
	if (VirtualProtectEx(hProcess, (LPVOID)dwAddr, 1, PAGE_NOACCESS, &m_dwOldProtect))
	{
		return TRUE;
	}
	return FALSE;
}

BOOL CBmBp::RemoveBmBreakPoint(HANDLE hProcess)
{
	//修改内存分页属性，改为先前权限
	DWORD OldProtect;//不需要，值应该为PAGE_NOACCESS
	if (VirtualProtectEx(hProcess, (LPVOID)m_dwAddr, 1, m_dwOldProtect, &OldProtect))
	{
		return TRUE;
	}
	return FALSE;
}

BOOL CBmBp::ReSetBmBreakPoint(HANDLE hProcess)
{
	//修改内存分页属性，改为没有任何访问权限
	if (VirtualProtectEx(hProcess, (LPVOID)m_dwAddr, 1, PAGE_NOACCESS, &m_dwOldProtect))
	{
		return TRUE;
	}
	return FALSE;
}

