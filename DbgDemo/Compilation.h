#pragma once
#include <windows.h>

class CCompilation
{
public:
	CCompilation();
	~CCompilation();
	bool GetOpcode(HANDLE hProcess);
};
