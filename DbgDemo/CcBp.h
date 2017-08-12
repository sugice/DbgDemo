#pragma once
#include "windows.h"
#include "MyType.h"
#include <vector>
using std::vector;

class CCcBp
{
public:
	CCcBp();
	~CCcBp();
public:
	BOOL SetBsBreakPoint(DWORD dwAddr, HANDLE hProcess);
	BOOL RemoveBsBreakPoint(DWORD dwAddr, HANDLE hProcess);
	BOOL EipSubOne(DWORD dwThreadId);
private:
	vector<BYTE> m_vecOldByte;
	vector<BYTE> m_vecOldByteAddr;
	BYTE  m_oldByte;//下断点位置原来的内容，恢复用
};

