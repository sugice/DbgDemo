#include "stdafx.h"
#include "FindTaskmgr.h"
#include <Shlwapi.h>

#define DBGOUT(format,error) \
printf("%s , %s , 第%d行: " ## format , __FILE__, __FUNCTION__ ,__LINE__,error)//用来报错的宏

CFindTaskmgr::CFindTaskmgr()
{
}


CFindTaskmgr::~CFindTaskmgr()
{
}


void CFindTaskmgr::CreatDetectionThread()
{
	CreateThread(NULL, NULL, CycleDetectionTaskmgr, (LPVOID)this, NULL, NULL);
}


DWORD WINAPI CFindTaskmgr::CycleDetectionTaskmgr(LPVOID lpParam)
{
	CFindTaskmgr *pThis = (CFindTaskmgr*)lpParam;
	if (pThis->OpenDllInjector())
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
	
}

BOOL CFindTaskmgr::OpenDllInjector()
{
	while (true)
	{
		// 遍历
		HANDLE hProcessSnap;//进程快照句柄
		PROCESSENTRY32 stcPe32 = { 0 };//进程快照信息
		stcPe32.dwSize = sizeof(PROCESSENTRY32);
		//1.创建一个进程相关的快照句柄
		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE) return FALSE;
		//2通过进程快照句柄获取第一个进程信息
		if (!Process32First(hProcessSnap, &stcPe32)) {
			CloseHandle(hProcessSnap);
			return FALSE;
		}
		//3循环遍历进程信息
		do {
			//3.1获取进程名
			if (StrCmpW(stcPe32.szExeFile, L"Taskmgr.exe") == 0)
			{
				char temp[10] = { 0 };
				sprintf(temp, "%d", stcPe32.th32ProcessID);
				if (!WriteTOFile(L"TaskmgrPID.txt", temp))
				{
					DBGOUT("%s\n", "将任务管理器PID写入文件失败！");
				}
				STARTUPINFO si = { sizeof(STARTUPINFO) };
				PROCESS_INFORMATION pi;
				
				// 3. 以管理员权限重新打开进程
				SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
				sei.lpVerb = L"runas";      // 请求提升权限
				sei.lpFile = L"..\\x64\\Debug\\DllInjector.exe"; // 可执行文件路径
				sei.lpParameters = NULL;          // 不需要参数
				sei.nShow = SW_SHOWNORMAL; // 正常显示窗口
				//以管理员权限打开注入器进程
				if (ShellExecuteEx(&sei)){
					return TRUE;
				}
				else{
					return FALSE;
				}
			}
		} while (Process32Next(hProcessSnap, &stcPe32));
		CloseHandle(hProcessSnap);
		Sleep(1000);
	}
}


BOOL CFindTaskmgr::WriteTOFile(WCHAR* strPath, char* szContext)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(strPath,	/* 文件路径 */
		GENERIC_READ | GENERIC_WRITE,	/*访问方式*/
		0,								/*文件共享方式*/
		NULL,							/*安全描述符*/
		OPEN_EXISTING,					/*文件创建标志*/
		FILE_ATTRIBUTE_NORMAL,			/*文件标志和属性*/
		NULL							/*模板句柄,默认填NULL*/
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("打开文件失败,文件不存在\n");
		return FALSE;
	}
	int size = strlen(szContext);
	szContext[size] = '\r';
	szContext[size + 1] = '\n';
	szContext[size + 2] = '\0';
	// 设置文件读写位置
	SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	// 写入文件.
	DWORD dwWrite = 0;
	WriteFile(hFile,
		szContext,					/*要写入的缓冲区的首地址*/
		strlen(szContext),			/*要写入到文件中的字节数*/
		&dwWrite,					/*实际写入的字节数*/
		NULL);

	CloseHandle(hFile);
	return TRUE;
}
