// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "detours/detours.h"
#include <TlHelp32.h>

#ifdef _WIN64
#pragma comment(lib,"detours\\lib.X64\\\detours.lib")
#else
#pragma comment(lib,"detours\\lib.X86\\\detours.lib")
#endif // _WIN64

typedef HANDLE (WINAPI *FnOpenProcess)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
);

FnOpenProcess g_pfnOpenProcess;
TCHAR g_processName[MAX_PATH];

HANDLE WINAPI MyOpenProcess(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
)
{
	// 要保护指定进程.
	// 通过进程名来保护.
	//  |- 需要遍历进程列表, 找到进程对应的PID
 	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
 	PROCESSENTRY32 procInfo = { sizeof(PROCESSENTRY32)};
 	Process32First(hSnap, &procInfo);
	
	// 进程遍历的代码还有bug
 	do 
 	{
 		if (_wcsicmp(g_processName, procInfo.szExeFile) == 0)
 		{
 			if (dwProcessId == procInfo.th32ProcessID)
 			{
 				return NULL;
 			}
 		}
 	} while (Process32Next(hSnap,&procInfo));

	// 调用原始API,完成打开进程的功能
	return g_pfnOpenProcess(dwDesiredAccess,
							bInheritHandle,
							dwProcessId);
}

extern"C" void _setInt();

// 对OpenProcess进行HOOK的函数
extern"C" _declspec(dllexport) void hook()
{
	//_setInt();// 手工构造一个软件断点,只用于调试

	HANDLE hFileMap = OpenFileMapping(GENERIC_READ, FALSE, L"Global\\HOOKTASKMGR");
	LPVOID pProcessName;
	pProcessName = MapViewOfFile(hFileMap, 
							 FILE_MAP_READ, 
							 0, 0, 
							 4096);
	wcscpy_s(g_processName, (WCHAR*)pProcessName);
	UnmapViewOfFile(pProcessName);
	CloseHandle(hFileMap);

	g_pfnOpenProcess = &OpenProcess;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&g_pfnOpenProcess, MyOpenProcess);
	DetourTransactionCommit();
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hook();
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

