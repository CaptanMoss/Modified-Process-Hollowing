#pragma once
#include "../Hooking/ldr.h"


__forceinline HRESULT WINAPI pCoInitializeEx(LPVOID pvReserved, DWORD  dwCoInit)
{
	HRESULT(WINAPI * pFunction)(LPVOID, DWORD);
	pFunction = (HRESULT(WINAPI*)(LPVOID, DWORD))_initialize(djb2_values[12], "CoInitializeEx",0);
	return pFunction(pvReserved, dwCoInit);
}

__forceinline HRESULT WINAPI pCoInitializeSecurity(
	PSECURITY_DESCRIPTOR        pSecDesc,
	LONG                        cAuthSvc,
	SOLE_AUTHENTICATION_SERVICE* asAuthSvc,
	void* pReserved1,
	DWORD                       dwAuthnLevel,
	DWORD                       dwImpLevel,
	void* pAuthList,
	DWORD                       dwCapabilities,
	void* pReserved3
)
{
	HRESULT(WINAPI * pFunction)(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*);
	pFunction = (HRESULT(WINAPI*)(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*))_initialize(djb2_values[12], "CoInitializeSecurity",0);
	return pFunction(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3);
}

__forceinline HRESULT WINAPI pCoCreateInstance(
	REFCLSID  rclsid,
	LPUNKNOWN pUnkOuter,
	DWORD     dwClsContext,
	REFIID    riid,
	LPVOID* ppv
)
{
	HRESULT(WINAPI * pFunction)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
	pFunction = (HRESULT(WINAPI*)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*))_initialize(djb2_values[12], "CoCreateInstance",0);
	return pFunction(rclsid, pUnkOuter, dwClsContext, riid, ppv);
}

__forceinline HRESULT WINAPI pCoSetProxyBlanket(
	IUnknown* pProxy,
	DWORD                    dwAuthnSvc,
	DWORD                    dwAuthzSvc,
	OLECHAR* pServerPrincName,
	DWORD                    dwAuthnLevel,
	DWORD                    dwImpLevel,
	RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	DWORD                    dwCapabilities
)
{
	HRESULT(WINAPI * pFunction)(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
	pFunction = (HRESULT(WINAPI*)(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD))_initialize(djb2_values[12], "CoSetProxyBlanket",0);
	return pFunction(pProxy, dwAuthnSvc, dwAuthzSvc, pServerPrincName, dwAuthnLevel, dwImpLevel, pAuthInfo, dwCapabilities);
}

__forceinline void WINAPI pCoUninitialize()
{
	VOID(WINAPI * pFunction)();
	pFunction = (VOID(WINAPI*)())_initialize(djb2_values[12], "CoUninitialize",0);
	return pFunction();
}


