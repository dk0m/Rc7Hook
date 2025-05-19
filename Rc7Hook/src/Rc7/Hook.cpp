#include "Hook.hpp"
#include<iostream>

PVOID AllocateJmpNearModule(PVOID modAddress, SIZE_T payloadSize) {
	MODULEINFO modInfo;
	GetModuleInformation(GetCurrentProcess(), (HMODULE)modAddress, &modInfo, sizeof(MODULEINFO));

	PVOID allocAddress = (PVOID)((DWORD_PTR)modInfo.lpBaseOfDll + modInfo.SizeOfImage);
	PVOID allocatedAddress = NULL;

	while (!allocatedAddress) {
		allocatedAddress = VirtualAlloc(allocAddress, payloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		allocAddress = (PVOID)((DWORD_PTR)allocAddress + NEAR_EAT_ALLOCATE_ALIGN);
	}

	return allocatedAddress;
}

Rc7Hook::Rc7Hook(LPCSTR ModuleName, LPCSTR ProcedureName, PVOID HookFunction, PVOID* OriginalFunction) {
	this->ModuleName = ModuleName;
	this->ProcedureName = ProcedureName;
	this->HookFunction = HookFunction;

	this->OriginalFunction = OriginalFunction;
	this->OriginalRva = 0;

	this->peImage = ParsePeImage(NULL);
	this->modImage = ParsePeImage(ModuleName);

	this->state = new HookState{false, false};
}

Rc7Hook::~Rc7Hook() {
	delete this->state;
}

bool Rc7Hook::Enable() {
	Pe peImage = this->peImage;
	auto state = this->state;

	auto peBase = (DWORD_PTR)peImage.ImageBase;
	auto importDescriptor = peImage.ImportDescriptor;

	// Hook IAT //
	while (importDescriptor->Name != NULL) {
		
		LPCSTR libName = (LPCSTR)(peBase + importDescriptor->Name);

		if (!_strcmpi(libName, this->ModuleName)) {

			PIMAGE_THUNK_DATA originalFirstThunk;
			PIMAGE_THUNK_DATA firstThunk;

			originalFirstThunk = (PIMAGE_THUNK_DATA)(peBase + importDescriptor->OriginalFirstThunk);
			firstThunk = (PIMAGE_THUNK_DATA)(peBase + importDescriptor->FirstThunk);

			while (originalFirstThunk->u1.AddressOfData != NULL) {

				PIMAGE_IMPORT_BY_NAME funcName = (PIMAGE_IMPORT_BY_NAME)(peBase + originalFirstThunk->u1.AddressOfData);

				if (!_strcmpi(funcName->Name, this->ProcedureName)) {

					(*this->OriginalFunction) = (PVOID)firstThunk->u1.Function;

					DWORD oldProtection;
					VirtualProtect(&firstThunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtection);

					firstThunk->u1.Function = (ULONGLONG)this->HookFunction;
					
					VirtualProtect(&firstThunk->u1.Function, sizeof(PVOID), oldProtection, &oldProtection);

					state->isIatHooked = true;

					break;
				}

				firstThunk++;
				originalFirstThunk++;
			}
		}

		importDescriptor++;
	}

	// Hook EAT //
	Pe peModule = this->modImage;

	auto exportDirectory = peModule.ExportDirectory;
	auto modBase = (DWORD_PTR)peModule.ImageBase;

	PDWORD funcNames = (PDWORD)(modBase + exportDirectory->AddressOfNames);
	PDWORD funcAddrs = (PDWORD)(modBase + exportDirectory->AddressOfFunctions);
	PWORD funcNameOrds = (PWORD)(modBase + exportDirectory->AddressOfNameOrdinals);

	PVOID hookFunction = this->HookFunction;

	#ifdef _WIN64
		BYTE jmpByteArray[12] = { 0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xE0 }; // mov rax; jmp rax
	#else
		BYTE jmpByteArray[7] = { 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0 }; // mov eax; jmp eax
	#endif
	
	for (size_t i = 0; i < exportDirectory->NumberOfFunctions; i++)
	{
		LPCSTR fnName = (LPCSTR)(modBase + funcNames[i]);
		WORD fnOrd = (WORD)(funcNameOrds[i]);
		DWORD fnRva = (DWORD)(funcAddrs[fnOrd]);
		
		if (!_strcmpi(fnName, this->ProcedureName)) {

			this->OriginalRva = fnRva;

			PVOID jmpAddr = AllocateJmpNearModule(peModule.ImageBase, sizeof(jmpByteArray));
			memcpy(&jmpByteArray[2], &hookFunction, sizeof(PVOID));

			memcpy(jmpAddr, jmpByteArray, sizeof(jmpByteArray));

			DWORD hookFnRva = (DWORD)((DWORD_PTR)jmpAddr - (DWORD)peModule.ImageBase);
			
			DWORD oldProtection;
			VirtualProtect(&(funcAddrs[fnOrd]), sizeof(DWORD), PAGE_READWRITE, &oldProtection);

			funcAddrs[fnOrd] = hookFnRva;

			VirtualProtect(&(funcAddrs[fnOrd]), sizeof(DWORD), oldProtection, &oldProtection);

			state->isEatHooked = true;

			break;
		}
	}
	
	return state->isIatHooked || state->isEatHooked;
}


bool Rc7Hook::Disable() {

	Pe peImage = this->peImage;
	auto state = this->state;

	if (!state->isIatHooked && !state->isEatHooked) {
		return false; // no hooked data directory entries, return
	}

	auto peBase = (DWORD_PTR)peImage.ImageBase;
	auto importDescriptor = peImage.ImportDescriptor;

	// Restore IAT (if it was hooked) //
	while (importDescriptor->Name != NULL) {

		LPCSTR libName = (LPCSTR)(peBase + importDescriptor->Name);

		if (!_strcmpi(libName, this->ModuleName)) {

			PIMAGE_THUNK_DATA originalFirstThunk;
			PIMAGE_THUNK_DATA firstThunk;

			originalFirstThunk = (PIMAGE_THUNK_DATA)(peBase + importDescriptor->OriginalFirstThunk);
			firstThunk = (PIMAGE_THUNK_DATA)(peBase + importDescriptor->FirstThunk);

			while (originalFirstThunk->u1.AddressOfData != NULL) {
				PIMAGE_IMPORT_BY_NAME funcName = (PIMAGE_IMPORT_BY_NAME)(peBase + originalFirstThunk->u1.AddressOfData);

				if (!_strcmpi(funcName->Name, this->ProcedureName) && state->isIatHooked) {
					DWORD oldProtection;
					VirtualProtect(&firstThunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtection);

					firstThunk->u1.Function = (ULONGLONG)(*this->OriginalFunction);

					VirtualProtect(&firstThunk->u1.Function, sizeof(PVOID), oldProtection, &oldProtection);

					state->isIatHooked = false;

					break;
				}

				firstThunk++;
				originalFirstThunk++;
			}
		}

		importDescriptor++;
	}

	// Restore EAT (if it was hooked) //
	Pe peModule = this->modImage;

	auto exportDirectory = peModule.ExportDirectory;
	auto modBase = (DWORD_PTR)peModule.ImageBase;

	PDWORD funcNames = (PDWORD)(modBase + exportDirectory->AddressOfNames);
	PDWORD funcAddrs = (PDWORD)(modBase + exportDirectory->AddressOfFunctions);
	PWORD funcNameOrds = (PWORD)(modBase + exportDirectory->AddressOfNameOrdinals);

	for (size_t i = 0; i < exportDirectory->NumberOfNames; i++)
	{
		LPCSTR fnName = (LPCSTR)(modBase + funcNames[i]);
		WORD fnOrd = (WORD)(funcNameOrds[i]);
		DWORD fnRva = (DWORD)(funcAddrs[fnOrd]);

		if (!_strcmpi(fnName, this->ProcedureName) && state->isEatHooked) {
			DWORD oldProtection;
			VirtualProtect(&(funcAddrs[fnOrd]), sizeof(DWORD), PAGE_READWRITE, &oldProtection);

			funcAddrs[fnOrd] = this->OriginalRva;

			VirtualProtect(&(funcAddrs[fnOrd]), sizeof(DWORD), oldProtection, &oldProtection);

			state->isEatHooked = false;

			break;
		}
	}

	return !state->isIatHooked || !state->isEatHooked;
}
