#include<iostream>

#include "../examples.h"

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

void examples::runMessageBoxAHook() {
	Rc7Hook msgboxHook { "user32.dll", "MessageBoxA", hookMessageBoxA, (PVOID*)&orgMessageBoxA };
	
	if (msgboxHook.Enable()) {
		printf("[+] Enabled MessageBoxA Hook!\n");
	}
	else {
		printf("[-] Failed to Enable MessageBoxA Hook.\n");
	}

	MessageBoxA(
		NULL,
		"This Will Be Hooked!",
		":(",
		0
	);

	printf("[*] Press a Key to Unhook.\n");
	getchar();

	if (msgboxHook.Disable()) {
		printf("[+] Disabled MessageBoxA Hook!\n");
	}
	else {
		printf("[-] Failed to Disable MessageBoxA Hook.\n");
	}

	MessageBoxA(
		NULL,
		"This Will Run Fine!",
		":)",
		0
	);

}