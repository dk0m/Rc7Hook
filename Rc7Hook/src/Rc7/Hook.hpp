#include<windows.h>
#include<Psapi.h>
#include "Pe.h"

#define NEAR_EAT_ALLOCATE_ALIGN 0x10000

typedef struct HookState {
	bool isIatHooked;
	bool isEatHooked;
} HookState;

class Rc7Hook {

private:
	DWORD OriginalRva;
	Pe peImage;
	Pe modImage;
	HookState* state;

public:
	LPCSTR ModuleName;
	LPCSTR ProcedureName;
	PVOID HookFunction;
	PVOID* OriginalFunction;

	Rc7Hook(LPCSTR ModuleName, LPCSTR ProcedureName, PVOID HookFunction, PVOID* OriginalFunction);
	~Rc7Hook();

	bool Enable(); // Hook Both IAT And EAT 

	bool Disable(); // UnHook Both IAT and EAT
};