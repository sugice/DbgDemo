#pragma once
#include <windows.h>
#include "MyType.h"
#include <list>
#include "TfBp.h"
#include "CcBp.h"
#include <string>
#include "LordPe.h"
#include "BhBp.h"
#include "BmBp.h"
#include <TlHelp32.h>
#include "FindTaskmgr.h"
using std::string;
using std::list;


typedef struct _MyLOAD_DLL_DEBUG_INFO {
	HANDLE hFile;
	LPVOID lpBaseOfDll;
	DWORD dwDebugInfoFileOffset;
	DWORD nDebugInfoSize;
	LPVOID lpImageName;
	WORD fUnicode;
} MyLOAD_DLL_DEBUG_INFO, *LPMyLOAD_DLL_DEBUG_INFO;

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

	// 异常调试事件---------↑----------
	// 打印寄存器信息
	VOID ShowRegisterInfo(CONTEXT& ct);
	// 等待用户输入调试命令
	VOID WaitforUserCommand();
	// 用户命令
	// b命令
	void UserCommandB(CHAR* pCommand);

	// u命令
	void UserCommandDisasm(CHAR* pCommand);
	//获取堆栈信息
	BOOL GetStackInfo(DWORD dwThreadId, HANDLE hProcess);
	//遍历被调试进程模块
	BOOL EnumModules(DWORD dwPid);
	//打印模块信息
	VOID PrintfModulesInfo();

	//判断条件断点是否命中
	BOOL IsConditionBreakPoint(DWORD dwThreadId);
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
	vector<MyLOAD_DLL_DEBUG_INFO> m_vecLoadDllInfo;
	vector<MODULEENTRY32> m_vecModule;
	DWORD m_bmAddr;//记录内存访问断点地址，只允许设置一个内存访问断点
	CTfBp* m_pTfBp;//设置单步断点的类对象指针
	CCcBp* m_pCcBp;//设置软件断点类对象指针
	CBhBp m_BhBp;//设置硬件断点类对象
	CBmBp m_bmBp;//设置内存断点类对象
	CFindTaskmgr m_findTaskmgr;//检测任务管理器是否打开的类

	CLordPe* m_pLordPe;//解析pe类指针

	BOOL isSystemBp;//是否是第一个系统断点
	BOOL m_isUserTf;//是否是用户单步执行操作设置的TF断点
	BOOL m_isCcTf;//是否是为了重设软件断点设置的TF断点
	BOOL m_isBhTf;//是否是为了重设硬件断点设置的TF断点
	BOOL m_isBmTf;//是否是为了重设内存断点设置的TF断点
	BOOL m_notWaitUser;//是否要接受用户输入
	DWORD m_dwOep;//被调试进程OEP
	DWORD m_dwBaseAddr;//被调试进程基地址

	DWORD m_dwLeft;//用来记录表达式左操作寄存器类型
	DWORD m_dwSymbol;//用来记录表达式操作符号
	DWORD m_dwRight;//用来记录表达式右操作数
};

