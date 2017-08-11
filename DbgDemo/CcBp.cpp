#include "stdafx.h"
#include "CcBp.h"




CCcBp::CCcBp()
{
}


CCcBp::~CCcBp()
{
}


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

BOOL CCcBp::RemoveBsBreakPoint(DWORD dwAddr, HANDLE hProcess)
{
	DWORD dwSize = 0;
	return WriteProcessMemory(hProcess, &dwAddr, &m_oldByte, 1, &dwSize);
}
