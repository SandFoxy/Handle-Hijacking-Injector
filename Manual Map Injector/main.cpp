#define _HAS_STD_BYTE  0
#include "injector.h"
#include "hijacking.h"

#include <string>
#include <iostream>

using namespace std;

OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security)
{
	OBJECT_ATTRIBUTES object;

	object.Length = sizeof(OBJECT_ATTRIBUTES);
	object.ObjectName = name;
	object.Attributes = attributes;
	object.RootDirectory = hRoot;
	object.SecurityDescriptor = security;

	return object;
}

SYSTEM_HANDLE_INFORMATION* hInfo; //holds the handle information

//the handles we will need to use later on
HANDLE procHandle = NULL;
HANDLE hProcess = NULL;
HANDLE HijackedHandle = NULL;

bool IsHandleValid(HANDLE handle) //litle bit optimized
{
	if (handle && handle != INVALID_HANDLE_VALUE)
		return true;

	return false;
}

bool IsCorrectTargetArchitecture(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {
		printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

DWORD GetProcessIdByName(wchar_t* name) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (_wcsicmp(entry.szExeFile, name) == 0) {
				CloseHandle(snapshot); //thanks to Pvt Comfy
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}

#define LOG(text) std::cout << text << std::endl;

HANDLE HijackExistingHandle(DWORD dwTargetProcessId)
{
	HMODULE Ntdll = GetModuleHandleA("ntdll");

	_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(Ntdll, "RtlAdjustPrivilege");

	boolean OldPriv;

	RtlAdjustPrivilege(SeDebugPriv, TRUE, FALSE, &OldPriv);

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(Ntdll, "NtQuerySystemInformation");

	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(Ntdll, "NtDuplicateObject");
	_NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(Ntdll, "NtOpenProcess");
	OBJECT_ATTRIBUTES Obj_Attribute = InitObjectAttributes(NULL, NULL, NULL, NULL);

	CLIENT_ID clientID = { 0 };

	DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);

	hInfo = (SYSTEM_HANDLE_INFORMATION*) new byte[size];

	ZeroMemory(hInfo, size);

	NTSTATUS NtRet = NULL;

	do
	{
		delete[] hInfo;

		size *= 1.5;
		try
		{
			hInfo = (PSYSTEM_HANDLE_INFORMATION) new byte[size];
		}
		catch (std::bad_alloc)
		{

			LOG("Bad Heap Allocation");
			Sleep(5000);
			exit(0);

		}
		Sleep(1);

	} while ((NtRet = NtQuerySystemInformation(SystemHandleInformation, hInfo, size, NULL)) == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(NtRet))
	{
		LOG("NtQuerySystemInformation Failed");
		Sleep(5000);
		exit(0);
	}

	for (unsigned int i = 0; i < hInfo->HandleCount; ++i)
	{
		static DWORD NumOfOpenHandles;

		GetProcessHandleCount(GetCurrentProcess(), &NumOfOpenHandles);

		if (NumOfOpenHandles > 50)
		{
			LOG("Error Handle Leakage Detected");
			Sleep(5000);
			exit(0);
		}


		if (!IsHandleValid((HANDLE)hInfo->Handles[i].Handle) || hInfo->Handles[i].ObjectTypeNumber != ProcessHandleType)
			continue;

		clientID.UniqueProcess = (DWORD*)hInfo->Handles[i].ProcessId;

		procHandle ? CloseHandle(procHandle) : 0;

		NtRet = NtOpenProcess(&procHandle, PROCESS_DUP_HANDLE, &Obj_Attribute, &clientID);
		if (!IsHandleValid(procHandle) || !NT_SUCCESS(NtRet))
		{
			continue;
		}

		NtRet = NtDuplicateObject(procHandle, (HANDLE)hInfo->Handles[i].Handle, NtCurrentProcess, &HijackedHandle, PROCESS_ALL_ACCESS, 0, 0);
		if (!IsHandleValid(HijackedHandle) || !NT_SUCCESS(NtRet))
		{

			continue;
		}

		if (GetProcessId(HijackedHandle) != dwTargetProcessId) {
			CloseHandle(HijackedHandle);
			continue;
		}
		hProcess = HijackedHandle;
		break;
	}
	return hProcess;

}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
	wchar_t* dllPath;
	DWORD PID;

	LOG((R"(
 /$$   /$$                 /$$                      /$$$$$$                     
| $$  | $$                | $$                     /$$__  $$                    
| $$  | $$ /$$   /$$  /$$$$$$$  /$$$$$$   /$$$$$$ | $$  \__/  /$$$$$$  /$$$$$$$ 
| $$$$$$$$| $$  | $$ /$$__  $$ /$$__  $$ /$$__  $$| $$ /$$$$ /$$__  $$| $$__  $$
| $$__  $$| $$  | $$| $$  | $$| $$  \__/| $$  \ $$| $$|_  $$| $$$$$$$$| $$  \ $$
| $$  | $$| $$  | $$| $$  | $$| $$      | $$  | $$| $$  \ $$| $$_____/| $$  | $$
| $$  | $$|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$/|  $$$$$$/|  $$$$$$$| $$  | $$
|__/  |__/ \____  $$ \_______/|__/       \______/  \______/  \_______/|__/  |__/
           /$$  | $$                                                            
          |  $$$$$$/                                                            
           \______/                                                              
)"));
	LOG("\n\nManual Map Injector Using Handle Hijack");
	//LOG(xo

	if (argc == 3) {
		dllPath = argv[1];
		PID = GetProcessIdByName(argv[2]);
	}
	else if (argc == 2) {
		dllPath = argv[1];
		std::string pname;
		printf("Process Name: ");
		std::getline(std::cin, pname);

		char* vIn = (char*)pname.c_str();
		wchar_t* vOut = new wchar_t[strlen(vIn) + 1];
		mbstowcs_s(NULL, vOut, strlen(vIn) + 1, vIn, strlen(vIn));
		PID = GetProcessIdByName(vOut);
	}
	else {
		printf("Invalid Params\n");
		printf("Usage: dll_path [process_name]\n");
		system("pause");
		return 0;
	}

	if (PID == 0) {
		printf("Process not found\n");
		system("pause");
		return -1;
	}

	printf("Process pid: %d\n", PID);

	HANDLE hProc = HijackExistingHandle(PID);
	if (!hProc) {
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		system("PAUSE");
		return -2;
	}

	if (!IsCorrectTargetArchitecture(hProc)) {
		printf("Invalid Process Architecture.\n");
		CloseHandle(hProc);
		system("PAUSE");
		return -3;
	}

	if (GetFileAttributes(dllPath) == INVALID_FILE_ATTRIBUTES) {
		printf("Dll file doesn't exist\n");
		CloseHandle(hProc);
		system("PAUSE");
		return -4;
	}

	std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

	if (File.fail()) {
		printf("Opening the file failed: %X\n", (DWORD)File.rdstate());
		File.close();
		CloseHandle(hProc);
		system("PAUSE");
		return -5;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		printf("Filesize invalid.\n");
		File.close();
		CloseHandle(hProc);
		system("PAUSE");
		return -6;
	}

	BYTE * pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData) {
		printf("Can't allocate dll file.\n");
		File.close();
		CloseHandle(hProc);
		system("PAUSE");
		return -7;
	}

	File.seekg(0, std::ios::beg);
	File.read((char*)(pSrcData), FileSize);
	File.close();

	printf("Mapping...\n");
	if (!ManualMapDll(hProc, pSrcData, FileSize)) {
		delete[] pSrcData;
		CloseHandle(hProc);
		printf("Error while mapping.\n");
		system("PAUSE");
		return -8;
	}
	delete[] pSrcData;

	CloseHandle(hProc);
	printf("OK\n");
	return 0;
}
