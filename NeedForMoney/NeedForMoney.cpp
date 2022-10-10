#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <tlhelp32.h>



uintptr_t GetBaseAddress(const HANDLE hProc) {
	if (hProc == NULL) return NULL;

	HMODULE lphModule[1024];
	DWORD lpcbNeeded(NULL);

	if (!EnumProcessModules(hProc, lphModule, sizeof(lphModule), &lpcbNeeded))
		return NULL;

	TCHAR szModName[MAX_PATH];
	if (!GetModuleFileNameEx(hProc, lphModule[0], szModName, sizeof(szModName) / sizeof(TCHAR))) // Mod size / tchar size = count
		return NULL;

	return (uintptr_t)lphModule[0];
}

uintptr_t FindPointer(HANDLE hProc, uintptr_t basePtr, std::vector<unsigned int> offsets)
{
	uintptr_t currentPtr = basePtr;

	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		uintptr_t newPtr;
		ReadProcessMemory(hProc, (BYTE*)currentPtr, &newPtr, sizeof(newPtr), nullptr);

		std::cout << "Tracing pointers ... 0x" << std::hex << currentPtr << " -> 0x" << newPtr << std::endl;

		currentPtr = newPtr + offsets[i];
	}

	return currentPtr;
}

HANDLE OpenProcessByName(const wchar_t* name, DWORD mode) {

	PROCESSENTRY32 procInfo;
	procInfo.dwSize = sizeof(procInfo);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &procInfo) == TRUE)
	{
		do
		{
			if (_wcsicmp(procInfo.szExeFile, name) == 0)
			{
				HANDLE hProc = OpenProcess(mode, FALSE, procInfo.th32ProcessID);
				CloseHandle(snapshot);
				return hProc;
			}
		} while (Process32Next(snapshot, &procInfo) == TRUE);
	}

	return NULL;
}

int main()
{
	HANDLE hProc = OpenProcessByName(L"NeedForSpeedHeat.exe", PROCESS_ALL_ACCESS);
	uintptr_t basePtr = GetBaseAddress(hProc);

	std::cout << "Base address: " << std::hex << basePtr << std::endl;

	std::vector<unsigned int> offsets = { 0x70, 0x38, 0x20, 0x38 };

	uintptr_t targetPtr = FindPointer(hProc, basePtr + 0x049DF7E0, offsets);

	int value = 0;

	ReadProcessMemory(hProc, (BYTE*)targetPtr, &value, sizeof(value), nullptr);

	std::cout << "Current money: " << std::dec << value << std::endl;
	std::cout << "New money amount: ";

	std::cin >> value;

	std::cout << "Writing 0x" << std::hex << value << " -> 0x" << targetPtr << std::endl;

	WriteProcessMemory(hProc, (BYTE*)targetPtr, &value, sizeof(value), nullptr);
}