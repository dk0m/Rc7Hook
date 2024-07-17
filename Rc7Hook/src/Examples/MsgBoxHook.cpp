#include "MsgBoxHook.hpp"

typedef int (WINAPI* typeMessageBoxA) (
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT uType
);

typeMessageBoxA orgMessageBoxA;

int hookMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	return orgMessageBoxA(hWnd, "Rc7Hooked!", ">:)", uType);
}

void RunMsgBoxHookExample() {
	Rc7Hook msgboxHook { "user32.dll", "MessageBoxA", hookMessageBoxA, (PVOID*)&orgMessageBoxA };
	
	msgboxHook.Enable();

	MessageBoxA(
		NULL,
		"This Will Be Hooked!",
		":(",
		0
	);

	msgboxHook.Disable();

	MessageBoxA(
		NULL,
		"This Will Run Fine!",
		":)",
		0
	);

}