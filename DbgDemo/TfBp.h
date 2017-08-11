#pragma once
#include "windows.h"
#include "MyType.h"

class CTfBp
{
public:
	CTfBp();
	~CTfBp();
	
	void UserCommandStepInto(DWORD dwThreadId);
};

