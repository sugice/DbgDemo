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
	BOOL RemoveAllBsBreakPoint(HANDLE hProcess);
	BOOL EipSubOne(DWORD dwThreadId);
	BOOL ReSetAllBsBreakPoint(HANDLE hProcess);
private:
	vector<BYTE> m_vecOldByte;
	vector<DWORD> m_vecOldByteAddr;
};

