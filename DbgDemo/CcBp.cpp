#include "stdafx.h"
#include "CcBp.h"




CCcBp::CCcBp()
{
}


CCcBp::~CCcBp()
{
}



//************************************
// Method:    SetBsBreakPoint
// FullName:  CCcBp::SetBsBreakPoint
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: DWORD dwAddr 断点地址
// Parameter: HANDLE hProcess 目标进程
// Function:  设置软件断点
//************************************
BOOL CCcBp::SetBsBreakPoint(DWORD dwAddr, HANDLE hProcess)
{
	//保存软件断点地址
	m_vecOldByteAddr.push_back(dwAddr);
	//读取进程内存，保存一个字节的数据
	DWORD dwSize = 0;
	BYTE oldByte;//下断点位置原来的内容，恢复用

	//修改内存分页属性，改为可读可写
	DWORD dwOldProtect;
	VirtualProtectEx(hProcess, (LPVOID)dwAddr, 1, PAGE_READWRITE, &dwOldProtect);

	if (!ReadProcessMemory(hProcess, (LPVOID)dwAddr, &oldByte, 1, &dwSize))
	{
		//将修改过的内存分页属性改回去
		VirtualProtectEx(hProcess, (LPVOID)dwAddr, 1, dwOldProtect, &dwOldProtect);
		return FALSE;
	}
	//保存软件断点地址处原内容
	m_vecOldByte.push_back(oldByte);
	//写入一个字节，\xcc就是int3指令的机器码
	BYTE cc = '\xcc';
	if (!WriteProcessMemory(hProcess, (LPVOID)dwAddr, &cc, 1, &dwSize))
	{
		//将修改过的内存分页属性改回去
		VirtualProtectEx(hProcess, (LPVOID)dwAddr, 1, dwOldProtect, &dwOldProtect);
		return FALSE;
	}

	//将修改过的内存分页属性改回去
	VirtualProtectEx(hProcess, (LPVOID)dwAddr, 1, dwOldProtect, &dwOldProtect);
	return TRUE;
}

//************************************
// Method:    RemoveBsBreakPoint
// FullName:  CCcBp::RemoveBsBreakPoint
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: DWORD dwAddr 断点地址
// Parameter: HANDLE hProcess 目标进程
// Function:  取消指定软件断点（软件断点触发时调用）
//************************************
BOOL CCcBp::RemoveBsBreakPoint(DWORD dwAddr, HANDLE hProcess)
{
	BYTE oldByte;
	//找到地址对应的原内容
	for (size_t i = 0; i < m_vecOldByteAddr.size(); i++)
	{
		if (m_vecOldByteAddr[i]==dwAddr)
		{
			oldByte = m_vecOldByte[i];
		}
	}
	//修改内存分页属性，改为可读可写
	DWORD dwOldProtect;
	VirtualProtectEx(hProcess, (LPVOID)dwAddr, 1, PAGE_READWRITE, &dwOldProtect);

	DWORD dwSize = 0;
	if (!WriteProcessMemory(hProcess, (LPVOID)dwAddr, &oldByte, 1, &dwSize))
	{
		//将修改过的内存分页属性改回去
		VirtualProtectEx(hProcess, (LPVOID)dwAddr, 1, dwOldProtect, &dwOldProtect);
		return FALSE;
	}
	//将修改过的内存分页属性改回去
	VirtualProtectEx(hProcess, (LPVOID)dwAddr, 1, dwOldProtect, &dwOldProtect);
	return TRUE;

}


//************************************
// Method:    RemoveAllBsBreakPoint
// FullName:  CCcBp::RemoveAllBsBreakPoint
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: HANDLE hProcess
// Function:  取消所有的软件断点（反汇编时调用）
//************************************
BOOL CCcBp::RemoveAllBsBreakPoint(HANDLE hProcess)
{
	for (size_t i = 0; i < m_vecOldByteAddr.size(); i++)
	{
		//修改内存分页属性，改为可读可写
		DWORD dwOldProtect;
		VirtualProtectEx(hProcess, (LPVOID)m_vecOldByteAddr[i], 1, PAGE_READWRITE, &dwOldProtect);

		DWORD dwSize = 0;
		if (!WriteProcessMemory(hProcess, (LPVOID)m_vecOldByteAddr[i], &m_vecOldByte[i], 1, &dwSize))
		{
			//将修改过的内存分页属性改回去
			VirtualProtectEx(hProcess, (LPVOID)m_vecOldByteAddr[i], 1, dwOldProtect, &dwOldProtect);
			return FALSE;
		}
		
		//将修改过的内存分页属性改回去
		VirtualProtectEx(hProcess, (LPVOID)m_vecOldByteAddr[i], 1, dwOldProtect, &dwOldProtect);

	}
	return TRUE;
}

//************************************
// Method:    EipSubOne
// FullName:  CCcBp::EipSubOne
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: DWORD dwThreadId
// Function:  将被调试线程EIP减一
//************************************
BOOL CCcBp::EipSubOne(DWORD dwThreadId)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dwThreadId);
	if (NULL==hThread)
	{
		return FALSE;
	}
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	if (!GetThreadContext(hThread, &ct))
	{
		return FALSE;
	}
	ct.Eip--;
	if (!SetThreadContext(hThread, &ct))
	{
		return FALSE;
	}	
	CloseHandle(hThread);
	return TRUE;
}

//************************************
// Method:    ReSetAllBsBreakPoint
// FullName:  CCcBp::ReSetAllBsBreakPoint
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: HANDLE hProcess
// Function:  将全部的软件断点恢复
//************************************
BOOL CCcBp::ReSetAllBsBreakPoint(HANDLE hProcess)
{
	//写入一个字节，\xcc就是int3指令的机器码
	BYTE cc = '\xcc';
	DWORD dwSize;
	for (auto each : m_vecOldByteAddr)
	{
		//修改内存分页属性，改为可读可写
		DWORD dwOldProtect;
		VirtualProtectEx(hProcess, (LPVOID)each, 1, PAGE_READWRITE, &dwOldProtect);

		if (!WriteProcessMemory(hProcess, (LPVOID)each, &cc, 1, &dwSize))
		{
			//将修改过的内存分页属性改回去
			VirtualProtectEx(hProcess, (LPVOID)each, 1, dwOldProtect, &dwOldProtect);
			return FALSE;
		}
		//将修改过的内存分页属性改回去
		VirtualProtectEx(hProcess, (LPVOID)each, 1, dwOldProtect, &dwOldProtect);
	}
	return TRUE;
}