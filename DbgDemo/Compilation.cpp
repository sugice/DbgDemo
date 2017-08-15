#include "stdafx.h"
#include "Compilation.h"

//1. 包含头文件
#include "keystone/keystone.h"
#include "DbgEngine.h"

//2. 包含静态库
#pragma comment (lib,"keystone/x86/keystone_x86.lib")

CCompilation::CCompilation()
{
}


CCompilation::~CCompilation()
{
}

bool CCompilation::GetOpcode(unsigned char* opcode, size_t& nOpcodeSize, int& nAddr)
{
	ks_engine *pengine = NULL;
	if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pengine)) {
		printf("反汇编引擎初始化失败\n");
		return false;
	}


	// 汇编指令
	// 可以使用分号，或者换行符将指令分隔开
	char asmCode[MAX_INPUT] = { 0 };
	printf("请输入需要插入的汇编指令：");
	gets_s(asmCode, MAX_INPUT);
	printf("请输入需要插入指令的首地址：");
	scanf("%X", nAddr);

	opcode = NULL; // 汇编得到的opcode的缓冲区首地址
	int nRet = 0; // 保存函数的返回值，用于判断函数是否执行成功
	size_t stat_count = 0; // 保存成功汇编的指令的条数

	nRet = ks_asm(pengine, /* 汇编引擎句柄，通过ks_open函数得到*/
		asmCode, /*要转换的汇编指令*/
		nAddr, /*汇编指令所在的地址*/
		&opcode,/*输出的opcode*/
		&nOpcodeSize,/*输出的opcode的字节数*/
		&stat_count /*输出成功汇编的指令的条数*/
	);

	// 返回值等于-1时反汇编错误
	if (nRet == -1) {
		// 输出错误信息
		// ks_errno 获得错误码
		// ks_strerror 将错误码转换成字符串，并返回这个字符串
		printf("错误信息：%s\n", ks_strerror(ks_errno(pengine)));
		return false;
	}

	printf("一共转换了%d条指令\n", stat_count);
	// 释放空间
	ks_free(opcode);
	// 关闭句柄
	ks_close(pengine);
	return true;
}

