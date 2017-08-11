#pragma once
#include "windows.h"
#include "MyType.h"

class CTfBp
{
public:
	CTfBp();
	~CTfBp();
	
	void SetTfBreakPoint(DWORD dwThreadId);
};

