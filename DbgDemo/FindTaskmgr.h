#pragma once
#include <windows.h>
#include <TlHelp32.h>

class CFindTaskmgr
{
public:
	CFindTaskmgr();
	~CFindTaskmgr();
	void CreatDetectionThread();
	static DWORD WINAPI CycleDetectionTaskmgr(LPVOID lpParam);
	BOOL OpenDllInjector();
	BOOL WriteTOFile(WCHAR* strPath, char* szContext);
};

