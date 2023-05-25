#pragma once

#include <wtypes.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <atlcomcli.h>

#include "function_definitions.h"
#include "../common/common.h"

#pragma comment(lib, "wbemuuid.lib")

IWbemLocator* pLoc = NULL;
IWbemServices* pSvc = NULL;

VOID WINAPI ph(VOID);
INT wmi_initialize(BSTR connect_point);
IEnumWbemClassObject* exec_query(BSTR Language, BSTR Query);
DWORD CreateProcess_API();
DWORD get_threadID(DWORD pid);