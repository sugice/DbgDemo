#pragma once
#include "windows.h"
class CBmBp
{
public:
	CBmBp();
	~CBmBp();
	BOOL SetBmBreakPoint(DWORD dwAddr, HANDLE hProcess);
	BOOL RemoveBmBreakPoint(HANDLE hProcess);
	BOOL ReSetBmBreakPoint(HANDLE hProcess);
private:
	DWORD m_dwOldProtect;//记录原先的内存分页保护属性
	DWORD m_dwAddr;//记录要设置的内存访问断点地址
};

