#include<windows.h>
#include<Psapi.h>
#include "Pe.h"

class Rc7Hook {

private:
	DWORD OriginalRva;
	Pe peImage;
	Pe modImage;

public:
	LPCSTR ModuleName;
	LPCSTR ProcedureName;
	PVOID HookFunction;
	PVOID* OriginalFunction;

	Rc7Hook(LPCSTR ModuleName, LPCSTR ProcedureName, PVOID HookFunction, PVOID* OriginalFunction);

	bool Enable(); // Hook Both IAT And EAT 

	bool Disable(); // UnHook Both IAT and EAT
};