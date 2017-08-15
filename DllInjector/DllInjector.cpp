// 注入和HOOK任务管理器保存指定进程.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <locale.h>
#include<fstream>
#include<iostream>  
#include <string>
#include <Shlwapi.h>
#pragma comment(lib,"Shlwapi.lib") 
using std::string;
using std::ifstream;

int main()
{
	// 设置控制台的字符集,为了避免Unicode的中文乱码
	//setlocale(LC_ALL, "chs");

	// 假设有一个DLL , 在DLL中有HOOK任务管理器的
	// OpenProcess函数的代码. 并且有保护指定进程
	// 不被关闭的代码.

	// 当前项目的功能: 将一个DLL注入到任务管理器中.
	// 要完成注入的功能, 需要做的事情:
	// 1. 得到任务管理器的进程句柄.并且,该进程句柄
	//    需要保存创建线程,读写虚拟内存的权限.
	// 2. 把DLL的路径写入到任务管理器进程内存中,备用.
	// 3. 创建一个远程线程, 将线程的回调函数设置为LoadLibrary
	//    将线程的附加参数设置为在任务管理器进程内存中的
	//    DLL文件路径.

	string buf;
	ifstream infile;
	infile.open(_T("..\\DbgDemo\\TaskmgrPID.txt"));
	if (!infile) {
		return 0;
	}
	//逐行读取直到读取完毕
	getline(infile, buf);
	infile.close();
	DWORD dwPid = 0;
	dwPid = StrToIntA(buf.c_str());


	// 打开任务管理器进程.
	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,FALSE,dwPid);
	if (hProc == INVALID_HANDLE_VALUE)
	{
		printf("打开失败,可能是权限不够\n");
		return 0;
	}

	char dllPath[MAX_PATH] = "D:\\Code\\DbgDemo\\x64\\Debug\\HookOpenProcess.dll";

	// 2. 将dll路径写入到任务管理器的进程内存中.
	LPVOID pBuff = NULL;
	pBuff = VirtualAllocEx(hProc,/*进程句柄*/
		NULL,/*指定的地址.*/
		4096,/*申请的大小*/
		MEM_RESERVE | MEM_COMMIT,/*内存的状态*/
		PAGE_READWRITE /*内存分页属性*/);
	if (pBuff == NULL)
	{
		printf("申请内存失败\n");
		return 0;
	}

	// 3. 把dll路径写入到新申请的内存中
	SIZE_T dwWrite = 0;
	WriteProcessMemory(hProc,  /*进程句柄*/
		pBuff,  /*要写入的地址*/
		dllPath, /*要写入缓冲区*/
		strlen(dllPath) + 1, /*缓冲区的字节数*/
		&dwWrite/*函数实际写入的字节数*/);

	// 4. 创建远程线程
	//    目的: 为了在远程进程中调用LoadLibrary
	HANDLE hThread = INVALID_HANDLE_VALUE;
	hThread = CreateRemoteThread(hProc, /*进程句柄*/
		NULL, /*安全描述符*/
		0,/*线程栈的字节数*/
		(LPTHREAD_START_ROUTINE)&LoadLibraryA,/*线程的回调函数*/
		pBuff,/*线程回调函数的附加参数*/
		0,
		0);
	// 等待线程退出.
	// 需要等待LoadLibrary函数的结束.
	WaitForSingleObject(hThread, -1);

	// 释放远程进程的空间.
	VirtualFreeEx(hProc, pBuff, 0, MEM_RELEASE);

	return 0;
}
