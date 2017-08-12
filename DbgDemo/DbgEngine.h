#pragma once
#include <windows.h>
#include "MyType.h"
#include <list>
#include "TfBp.h"
#include "CcBp.h"
#include <string>
#include "LordPe.h"
using std::string;


using std::list;

#define NUMOFBPTYPE 3

class CDbgEngine {
public:
#define MAX_INPUT 1024   // 控制台命令最大长度
	CDbgEngine();
	~CDbgEngine();
	// 调试主循环
	void DebugMain();
	// 调试事件分发
	DWORD DispatchDbgEvent(DEBUG_EVENT& de);
	// 调试事件---------↓----------
	// 进程创建事件
	DWORD OnCreateProcess(DEBUG_EVENT& de);
	// 模块加载事件
	DWORD OnLoadDll(DEBUG_EVENT& de);
	// 模块卸载事件
	DWORD OnUnLoadDll(DEBUG_EVENT& de);
	// 异常调试事件，项目时间都在这
	DWORD OnException(DEBUG_EVENT& de);
	// 调试事件---------↑----------

	// 异常调试事件---------↓----------
	// 软件断点异常
	DWORD OnExceptionCc(DEBUG_EVENT& de);
	// 单步异常
	DWORD OnExceptionSingleStep(DEBUG_EVENT& de);
	// 内存访问异常
	DWORD OnExceptionAccess(DEBUG_EVENT& de);
	// 异常调试事件---------↑----------
	// 打印寄存器信息
	VOID ShowRegisterInfo(CONTEXT& ct);
	// 等待用户输入调试命令
	DWORD WaitforUserCommand();
	// 用户命令
	// b命令
	void UserCommandB(CHAR* pCommand);

	// u命令
	void UserCommandDisasm(CHAR* pCommand);

	//获取被调试进程首地址
	LPCVOID getLoadAddress(DWORD dwProcessId);
private:
	// 反汇编函数
	void DisasmAtAddr(DWORD addr, DWORD dwCount = 10);
	UINT DBG_Disasm(HANDLE hProcess, LPVOID lpAddress, PWCHAR pOPCode, PWCHAR pASM, PWCHAR pComment);
private:
	// 调试进程的信息，进程创建事件的时候赋值OnCreateProcess
	PROCESS_INFORMATION m_pi;
	// 调试信息***!!指针!!****
	// 新一次的调试循环开始的时候重新赋值
	LPDEBUG_EVENT m_pDbgEvt;
private:
	list<DWORD> m_bpAddrList[NUMOFBPTYPE];//保存主动设置的断点地址和断点类型的list
	CTfBp* m_pTfBp;//设置单步断点的类对象指针
	CCcBp* m_pCcBp;//设置软件断点类对象
	CLordPe* m_pLordPe;//解析pe类指针
	BOOL isSystemBp;//是否是第一个系统断点
	BOOL m_isUserTf;//是否是用户单步执行操作设置的TF断点
	BOOL m_isCcTf;//是都是为了重设软件断点设置的TF断点
	DWORD m_dwOep;//被调试进程OEP
	DWORD m_dwBaseAddr;//被调试进程基地址
};

