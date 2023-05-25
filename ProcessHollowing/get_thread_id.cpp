#include "../ProcessHollowing/initialize_wmi.h"
#include "../common/common.h"

DWORD get_threadID(DWORD pid)
{

	IEnumWbemClassObject* enumerator = 0;
	IWbemClassObject* object = 0;
	DWORD ttid;
	string query = "SELECT * FROM Win32_Thread where ProcessHandle=";
	query += to_string(pid);

	enumerator = exec_query(bstr_t("WQL"), bstr_t(query.c_str())); //string concate pid

	VARIANT vtid;
	
	ULONG uReturn;
	
	for (;;) {
		HRESULT result = enumerator->Next(WBEM_INFINITE, 1, &object, &uReturn);
		if (uReturn == 0) {
			break;
		}

		result = object->Get((StringToWString("Handle")).c_str(), 0, &vtid, NULL, 0); //obfuscate et
		ttid = _wtoi(vtid.bstrVal);

		if (SUCCEEDED(result))
		{
			VariantClear(&vtid);
		}

		object->Release();
	}

	if (enumerator)
		enumerator->Release();


	return ttid;
}