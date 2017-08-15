#pragma once

class CCompilation
{
public:
	CCompilation();
	~CCompilation();
	bool GetOpcode(unsigned char* opcode, size_t& nOpcodeSize, int& nAddr);
};
