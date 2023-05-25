#include "windows.h"
#include "pe.h"
#include "ph_function_defenition.h"

DWORD FindRemotePEB()
{

	_NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)_initialize(djb2_values[0], (LPCSTR)"NtQueryInformationProcess",0);

	PROCESS_BASIC_INFORMATION* pBasicInfo =
		new PROCESS_BASIC_INFORMATION();

	DWORD dwReturnLength = 0;

	ntQueryInformationProcess
	(
		hProcess,
		0,
		pBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength
	);
	
	return pBasicInfo->PebBaseAddress;
}

PEB* ReadRemotePEB()
{
	DWORD dwPEBAddress = FindRemotePEB();

	PEB* pPEB = new PEB();

	BOOL bSuccess = pReadProcessMemory
	(
		hProcess,
		(LPCVOID)dwPEBAddress,
		pPEB,
		sizeof(PEB),
		0
	);

	if (!bSuccess)
		return 0;

	return pPEB;
}

PLOADED_IMAGE ReadRemoteImage()
{
	BYTE* lpBuffer = new BYTE[BUFFER_SIZE];

	BOOL bSuccess = pReadProcessMemory
	(
		hProcess,
		pPEB->ImageBaseAddress,
		lpBuffer,
		BUFFER_SIZE,
		0
	);

	if (!bSuccess)
		return 0;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;

	PLOADED_IMAGE pImage = new LOADED_IMAGE();

	pImage->FileHeader =
		(PIMAGE_NT_HEADERS32)(lpBuffer + pDOSHeader->e_lfanew);

	pImage->NumberOfSections =
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections =
		(PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew +
			sizeof(IMAGE_NT_HEADERS32));

	return pImage;
}

