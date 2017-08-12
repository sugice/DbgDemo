#include "stdafx.h"
#include "LordPe.h"
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

CLordPe::CLordPe()
{
}


CLordPe::~CLordPe()
{
	delete m_pBuf;
	m_pBuf = NULL;
}


//************************************
// Method:    GetDosHead
// FullName:  CLordPe::GetDosHead
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: LPCTSTR filePath
// Function:  将被调试进程PE文件内容读取进调试器进程内存空间
//************************************
BOOL CLordPe::GetDosHead(LPCTSTR filePath)
{
	// 1. 打开文件,将文件读取到内存.
	// CreateFile,ReadFile.
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);

	// 2. 申请内存空间
	BYTE* pBuf = new BYTE[dwFileSize];
	m_pBuf = pBuf;//保存起来，用于析构释放空间

	// 3. 将文件内容读取到内存中
	DWORD dwRead = 0;
	ReadFile(hFile, pBuf, dwFileSize, &dwRead, NULL);

	// 将缓冲区当成DOS头结构体来解析
	m_pDosHdr = (IMAGE_DOS_HEADER*)pBuf;//将DOS头指针保存起来

										// nt头,包含这文件头和扩展头
	IMAGE_NT_HEADERS* pNtHdr;
	pNtHdr = (IMAGE_NT_HEADERS*)(m_pDosHdr->e_lfanew + (DWORD)m_pDosHdr);

	// 判断是否是一个有效的pe文件
	if (m_pDosHdr->e_magic != IMAGE_DOS_SIGNATURE || pNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	return TRUE;
}

//************************************
// Method:    GetOep
// FullName:  CLordPe::GetOep
// Access:    public 
// Returns:   DWORD
// Qualifier:
// Function:  获取被调试进程OEP
//************************************
DWORD CLordPe::GetOep()
{
	// nt头,包含这文件头和扩展头
	IMAGE_NT_HEADERS* pNtHdr = (IMAGE_NT_HEADERS*)(m_pDosHdr->e_lfanew + (DWORD)m_pDosHdr);

	IMAGE_OPTIONAL_HEADER* pOptHdr = &(pNtHdr->OptionalHeader);//扩展头

	return pOptHdr->AddressOfEntryPoint;

}


//************************************
// Method:    getLoadAddress
// FullName:  CLordPe::getLoadAddress
// Access:    public 
// Returns:   LPCVOID
// Qualifier:
// Parameter: DWORD dwProcessId
// Function:  获取被调试进程加载基址
//************************************
LPCVOID CLordPe::getLoadAddress(DWORD dwProcessId)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, 0, dwProcessId);

	HMODULE hModule = LoadLibrary(TEXT("Ntdll.dll "));
	if (NULL == hModule)
		return NULL;

	typedef NTSTATUS(WINAPI *NtQueryInformationProcess)(
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength
		);
	NtQueryInformationProcess Func;

	Func = (NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION pbi = { 0 };

	LONG status = Func(hProcess, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (NULL != hModule)
		FreeLibrary(hModule);

	if (NULL != hProcess)
		CloseHandle(hProcess);

	return pbi.PebBaseAddress->Reserved3[1];
}