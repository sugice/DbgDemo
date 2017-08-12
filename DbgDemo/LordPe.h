#pragma once
#include "windows.h"


class CLordPe
{
public:
	CLordPe();
	~CLordPe();
	BOOL GetDosHead(LPCTSTR filePath);
	DWORD GetOep();
	LPCVOID getLoadAddress(DWORD dwProcessId);
private:
	BYTE* m_pBuf;//用于释放申请的空间
	PIMAGE_DOS_HEADER m_pDosHdr;//DOS头地址
};