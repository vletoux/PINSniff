#include <Windows.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tchar.h>

#define INITGUID
#include <guiddef.h>

#include <Setupapi.h>
#include <devguid.h>
#include <Cfgmgr32.h>
#include <Cfg.h>
#include "resource.h"

// session GUID to start, stop or save the session later
//
// {A6212851-CBDC-4885-9968-3D19FB52A631}
DEFINE_GUID(PersistentTracingSessionGuid, 
0xa6212851, 0xcbdc, 0x4885, 0x99, 0x68, 0x3d, 0x19, 0xfb, 0x52, 0xa6, 0x31);

// {6D1A873A-1B83-4700-8AF1-3A3B77C24C23}
DEFINE_GUID(LiveTracingSessionGuid, 
0x6d1a873a, 0x1b83, 0x4700, 0x8a, 0xf1, 0x3a, 0x3b, 0x77, 0xc2, 0x4c, 0x23);


// Tracing GUID to monitor
//
// {9d72d71d-9888-49ee-a33c-95e6bc931636}
DEFINE_GUID(TracingGuid, 
0x9d72d71d, 0x9888, 0x49ee, 0xa3, 0x3c, 0x95, 0xe6, 0xbc, 0x93, 0x16, 0x36);

GUID GuidToTrace[] = {TracingGuid};

BOOL IsPersistentLoggingEnabled()
{
	HKEY hkResult;
	DWORD Status;
	BOOL fReturn = FALSE;
	Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"),0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE,&hkResult);
	if (Status == ERROR_SUCCESS) {
		fReturn = TRUE;
		RegCloseKey(hkResult);
	}
	return fReturn;
}


BOOL StopLogging(BOOL fPersistent)
{
	LONG err = 0;
	BOOL fReturn = FALSE;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];
		TCHAR LoggerName[1024];
	} Properties;
	
	__try
	{
		memset(&Properties, 0, sizeof(Properties));
		Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
		if (fPersistent)
		{
			Properties.TraceProperties.Wnode.Guid = PersistentTracingSessionGuid;
		}
		else
		{
			Properties.TraceProperties.Wnode.Guid = LiveTracingSessionGuid;
		}
		Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Properties.TraceProperties.LogFileMode = 4864; 
		Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(TCHAR);
		Properties.TraceProperties.MaximumFileSize = 8;
		err = ControlTrace(NULL, (fPersistent?TEXT("PINSniff"):TEXT("PINSniffLive")), &(Properties.TraceProperties),EVENT_TRACE_CONTROL_STOP);
		if (err != ERROR_SUCCESS && err != 0x00001069)
		{
			TCHAR szMessage[1024];
			_stprintf_s(szMessage,TEXT("ControlTrace 0x%08x"), err);
			OutputDebugString(szMessage);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(err);
	return fReturn;
}

BOOL StartLogging(BOOL fPersistent, DWORD dwLevel)
{
	BOOL fReturn = FALSE;
	TRACEHANDLE SessionHandle;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];
		TCHAR LoggerName[1024];
	} Properties;
	ULONG err = 0;
	TCHAR szLoggingDirectory[MAX_PATH+1];
	if (!ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\LogFiles\\WMI"), szLoggingDirectory, ARRAYSIZE(szLoggingDirectory)))
	{
		return FALSE;
	}
	__try
	{
		DWORD dwAttrib = GetFileAttributes(szLoggingDirectory);
		if (dwAttrib == INVALID_FILE_ATTRIBUTES || !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
		{
			if (!CreateDirectory(szLoggingDirectory,0))
			{
				err = GetLastError();
				__leave;
			}
		}
		memset(&Properties, 0, sizeof(Properties));
		Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
		if (fPersistent)
		{
			Properties.TraceProperties.Wnode.Guid = PersistentTracingSessionGuid;
		}
		else
		{
			Properties.TraceProperties.Wnode.Guid = LiveTracingSessionGuid;
		}
		Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Properties.TraceProperties.Wnode.ClientContext = 1;
		Properties.TraceProperties.FlushTimer = 1;
		Properties.TraceProperties.LogFileMode = EVENT_TRACE_DELAY_OPEN_FILE_MODE | EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_FILE_MODE_CIRCULAR;
		Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
		Properties.TraceProperties.MaximumFileSize = 8;
		Properties.TraceProperties.EnableFlags = 0xC;

		if (!ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl"), Properties.LogFileName, 1024))
		{
			err = GetLastError();
			__leave;
		}
		//_tcscpy_s(Properties.LoggerName,1024,TEXT("PINSniff"));
		err = StartTrace(&SessionHandle, (fPersistent?TEXT("PINSniff"):TEXT("PINSniffLive")), &(Properties.TraceProperties));
		if (err != ERROR_SUCCESS)
		{
			if (err== ERROR_ALREADY_EXISTS)
			{
				StopLogging(fPersistent);
				DeleteFile(Properties.LogFileName);
				err = StartTrace(&SessionHandle, (fPersistent?TEXT("PINSniff"):TEXT("PINSniffLive")), &(Properties.TraceProperties));
			}
			if (err != ERROR_SUCCESS)
			{
				TCHAR szMessage[1024];
				_stprintf_s(szMessage,TEXT("StartTrace 0x%08x"), err);
				OutputDebugString(szMessage);
				__leave;
			}
		}
		for (int i = 0; i < ARRAYSIZE(GuidToTrace); i++)
		{
			err = EnableTrace(TRUE,0x0C,dwLevel,GuidToTrace+i,SessionHandle);
			if (err != ERROR_SUCCESS)
			{
				TCHAR szMessage[1024];
				_stprintf_s(szMessage,TEXT("EnableTraceEx 0x%08x"), err);
				OutputDebugString(szMessage);
				__leave;
			}
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(err);
	return fReturn;
}


inline void GuidToStr(const GUID *guid,TCHAR szGuid[40])
{
	_stprintf_s(szGuid,40, TEXT("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}"),
             guid->Data1, guid->Data2, guid->Data3,
             guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
             guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

LONG WINAPI RegSetKeyValue(
	__in      HKEY hKey,
	__in      LPCTSTR lpSubKey,
	__in_opt  LPCTSTR lpValueName,
	__in      DWORD dwType,
	__in_opt  LPCVOID lpData,
	__in      DWORD cbData
)
{
	HKEY hTempKey = NULL;
	LONG lResult;
	lResult = RegCreateKeyEx(hKey, lpSubKey, 0,NULL,0,KEY_WRITE, NULL,&hTempKey,NULL);
	if (lResult != ERROR_SUCCESS) return lResult;
	lResult = RegSetValueEx( hTempKey,lpValueName,0, dwType,  (PBYTE) lpData,cbData);
	RegCloseKey(hTempKey);
	return lResult;
}


//*************************************************************
//
//  RegDelnodeRecurse()
//
//  Purpose:    Deletes a registry key and all its subkeys / values.
//
//  Parameters: hKeyRoot    -   Root key
//              lpSubKey    -   SubKey to delete
//
//  Return:     LSTATUS
//
//*************************************************************

BOOL RegDelnodeRecurse (HKEY hKeyRoot, LPTSTR lpSubKey)
{
	LPTSTR lpEnd;
	LONG lResult;
	DWORD dwSize;
	TCHAR szName[MAX_PATH*2];
	HKEY hKey;
	FILETIME ftWrite;

	// First, see if we can delete the key without having
	// to recurse.

	lResult = RegDeleteKey(hKeyRoot, lpSubKey);

	if (lResult == ERROR_SUCCESS) 
		return TRUE;

	lResult = RegOpenKeyEx (hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

	if (lResult != ERROR_SUCCESS) 
	{
		if (lResult == ERROR_FILE_NOT_FOUND) {
			return TRUE;
		} 
		else {
			return FALSE;
		}
	}

	// Check for an ending slash and add one if it is missing.

	lpEnd = lpSubKey + _tcsclen(lpSubKey);

	if (*(lpEnd - 1) != TEXT('\\')) 
	{
		*lpEnd =  TEXT('\\');
		lpEnd++;
		*lpEnd =  TEXT('\0');
	}

	// Enumerate the keys

	dwSize = MAX_PATH;
	lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
							NULL, NULL, &ftWrite);

	if (lResult == ERROR_SUCCESS) 
	{
		do {

			_tcscpy_s (lpEnd, MAX_PATH*2 - _tcsclen(lpSubKey), szName);
			if (!RegDelnodeRecurse(hKeyRoot, lpSubKey)) {
				break;
			}
			dwSize = MAX_PATH;
			lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
									NULL, NULL, &ftWrite);

		} while (lResult == ERROR_SUCCESS);
	}

	lpEnd--;
	*lpEnd = TEXT('\0');

	RegCloseKey (hKey);

	// Try again to delete the key.

	lResult = RegDeleteKey(hKeyRoot, lpSubKey);
	if (lResult == ERROR_SUCCESS) 
        return TRUE;

    return FALSE;
}

//*************************************************************
//
//  RegDelnode()
//
//  Purpose:    Deletes a registry key and all its subkeys / values.
//
//  Parameters: hKeyRoot    -   Root key
//              lpSubKey    -   SubKey to delete
//
//  Return:     TRUE if successful.
//              FALSE if an error occurs.
//
//*************************************************************


BOOL RegDelnode (HKEY hKeyRoot, LPTSTR lpSubKey)
{
    TCHAR szDelKey[MAX_PATH*2];

    _tcscpy_s (szDelKey, MAX_PATH*2, lpSubKey);
    return RegDelnodeRecurse(hKeyRoot, szDelKey);

}


BOOL ChangeSmartCardReaderFilter(BOOL fAdd)
{
	LONG lResult = 0;
	HKEY hKey = NULL;
	BYTE pbData[256] = {0};
	DWORD dwSize = sizeof(pbData);
	BOOL bFound = FALSE;
	lResult = RegOpenKeyEx (HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Class\\{50DD5230-BA8A-11D1-BF5D-0000F805F530}"), 0, KEY_ALL_ACCESS, &hKey);

	if (lResult != ERROR_SUCCESS) 
	{
		SetLastError(lResult);
		return FALSE;
	}
	lResult = RegQueryValueEx(hKey,TEXT("UpperFilters"),NULL,NULL,pbData,&dwSize);
	if (lResult != ERROR_SUCCESS && lResult != ERROR_FILE_NOT_FOUND) 
	{
		SetLastError(lResult);
		return FALSE;
	} else if (lResult == ERROR_FILE_NOT_FOUND)
	{
		dwSize = 2*sizeof(TCHAR);
	}

	if (dwSize + 40 > sizeof(pbData))
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	PTSTR szData = (PTSTR) pbData;
	while (szData[0] != 0) {
		if (_tcscmp(szData, TEXT("PINSniffDriver")) == 0) {
			bFound = TRUE;
			break;
		}
		szData += _tcslen(szData) + 1;
	}

	if (fAdd && !bFound) {
		memcpy(szData,  TEXT("PINSniffDriver\0"), 40);
		dwSize += sizeof(TEXT("PINSniffDriver"));
	} else if (!fAdd && bFound) {
		ULONG_PTR offset = (ULONG_PTR) szData - (ULONG_PTR) pbData;
		ULONG lenght = (ULONG) (dwSize - offset);
		for(ULONG i = 0; i < lenght; i++) {
			pbData[offset + i] = pbData[offset + sizeof(TEXT("PINSniffDriver"))];
		}
		dwSize -= sizeof(TEXT("PINSniffDriver"));
	} else {
		return TRUE;
	}

	if (((PTSTR)pbData)[0] == 0 && ((PTSTR)pbData)[1] == 0) {
		lResult = RegDeleteValue(hKey, TEXT("UpperFilters"));
		if (lResult != ERROR_SUCCESS) 
		{
			SetLastError(lResult);
			return FALSE;
		}
	}
	else
	{
		lResult = RegSetValueEx(hKey, TEXT("UpperFilters"), NULL, REG_MULTI_SZ, pbData, dwSize);
		if (lResult != ERROR_SUCCESS) 
		{
			SetLastError(lResult);
			return FALSE;
		}
	}
	RegCloseKey(hKey);
	return TRUE;
}

BOOL CreateDriverService(PTSTR szFile)
{
	SC_HANDLE hSC = NULL;
	SC_HANDLE hS = NULL;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
		if(!hSC)
		{
			dwError = GetLastError();
			__leave;
		}
		hS = OpenService(hSC, TEXT("PINSniffDriver"), SERVICE_START);
		if (hS)
		{
			fReturn = TRUE;
			__leave;
		}
		dwError = GetLastError();
		if(dwError != ERROR_SERVICE_DOES_NOT_EXIST)
		{
			__leave;
		}
		hS = CreateService(hSC, TEXT("PINSniffDriver"), L"PINSniff Driver", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, szFile, NULL, NULL, NULL, NULL, NULL);
		if (!hS)
		{
			dwError = GetLastError();
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hS) CloseServiceHandle(hS);
		if (hSC) CloseServiceHandle(hSC);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL RemoveDriverService()
{
	SC_HANDLE hSC = NULL;
	SC_HANDLE hS = NULL;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | DELETE);
		if(!hSC)
		{
			dwError = GetLastError();
			__leave;
		}
		hS = OpenService(hSC, TEXT("PINSniffDriver"), DELETE);
		if (!hS)
		{
			fReturn = TRUE;
			__leave;
		}
		if (!DeleteService(hS))
		{
			dwError = GetLastError();
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hS) CloseServiceHandle(hS);
		if (hSC) CloseServiceHandle(hSC);
	}
	SetLastError(dwError);
	return fReturn;
}


BOOL RestartSCReader()
{
	SP_DEVINFO_DATA DeviceInfoData;
	SP_PROPCHANGE_PARAMS params;
	memset(&params, 0, sizeof(SP_PROPCHANGE_PARAMS));
	params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	params.StateChange = DICS_PROPCHANGE;
	params.Scope = DICS_FLAG_CONFIGSPECIFIC;
	params.HwProfile = 0; // current profile

	HDEVINFO DeviceInfoSet = NULL;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		// we use CM_Get_DevNode_Status and not DIGCF_PRESENT to catch readers where the driver is in error
		DeviceInfoSet = SetupDiGetClassDevsEx(&GUID_DEVCLASS_SMARTCARDREADER,
                                        NULL,
                                        NULL,
                                        DIGCF_DEVICEINTERFACE,
                                        NULL,
                                        NULL,
                                        NULL);
		if (!DeviceInfoSet)
		{
			dwError = GetLastError();
			__leave;
		}
		// Get first device matching device criterion.
        for (DWORD i = 0; ; i++)
        {
            ULONG ulStatus, ulProblem;
			memset(&DeviceInfoData, 0,sizeof(DeviceInfoData));
			DeviceInfoData.cbSize = sizeof(DeviceInfoData);
			if (!SetupDiEnumDeviceInfo(DeviceInfoSet,
                i,
                &DeviceInfoData))
			{
				// if no items match filter, throw
				dwError = GetLastError();
				if( dwError != ERROR_NO_MORE_ITEMS)
					__leave;
				fReturn = TRUE;
				__leave;
			}
			
			dwError = CM_Get_DevNode_Status(&ulStatus, &ulProblem, DeviceInfoData.DevInst, 0);
            if (!dwError) {
				/*TCHAR szBuffer[2048];

				SetupDiGetDeviceRegistryProperty(
					DeviceInfoSet,
					&DeviceInfoData,
					SPDRP_HARDWAREID,
					NULL,
					(PBYTE) szBuffer,
					sizeof(szBuffer),
					NULL);*/

				if (!SetupDiSetClassInstallParams(DeviceInfoSet,&DeviceInfoData, (PSP_CLASSINSTALL_HEADER)&params, sizeof(SP_PROPCHANGE_PARAMS)))
				{
					dwError = GetLastError();
					__leave;
				}
			
				// stop and restart the device
				if (!SetupDiChangeState( DeviceInfoSet,
												&DeviceInfoData 
												))
       
				{
					dwError = GetLastError();
					__leave;
				}
			}
		}
	}
	__finally
	{
		if (DeviceInfoSet) SetupDiDestroyDeviceInfoList(DeviceInfoSet);
	}
	SetLastError(dwError);
	return fReturn;
}

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
        {
            //handle error
        }
    }
    return bIsWow64;
}

BOOL SaveSysDriver()
{
	HMODULE hModule = GetModuleHandle(NULL); // get the handle to the current module (the executable file)
	HRSRC hResource = NULL;
	HGLOBAL hMemory = NULL;
	PBYTE lpAddress = NULL;
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwRes = (!IsWow64()?IDR_SYSX86:IDR_SYSX64);
	TCHAR szDriverPath[MAX_PATH+1];
	__try
	{
		hResource = FindResource(hModule, MAKEINTRESOURCE(dwRes), TEXT("SYS")); // substitute RESOURCE_ID and RESOURCE_TYPE.
		if (!hResource)
		{
			dwError = GetLastError();
			__leave;
		}
		hMemory = LoadResource(hModule, hResource);
		if (!hMemory)
		{
			dwError = GetLastError();
			__leave;
		}
		DWORD dwSize = SizeofResource(hModule, hResource);
		lpAddress = (PBYTE) LockResource(hMemory);
		if (!lpAddress)
		{
			dwError = GetLastError();
			__leave;
		}
		if (!ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\drivers\\PINSniffDriver.sys"), szDriverPath, ARRAYSIZE(szDriverPath)))
		{
			dwError = GetLastError();
			__leave;
		}
		hFile = CreateFile(szDriverPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			dwError = GetLastError();
			__leave;
		}
		if (!WriteFile(hFile, lpAddress, dwSize, &dwSize, NULL))
		{
			dwError = GetLastError();
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL DeleteSysDriver()
{
	TCHAR szDriverPath[MAX_PATH+1];
	if (!ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\drivers\\PINSniffDriver.sys"), szDriverPath, ARRAYSIZE(szDriverPath)))
	{
		return FALSE;
	}
	return DeleteFile(szDriverPath);
}


BOOL EnableLogging(BOOL fPersistent)
{
	DWORD64 qdwValue;
	DWORD dwValue;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	TCHAR szGuid[40];
	TCHAR szFile[MAX_PATH+1];
	if (!ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl"), szFile, ARRAYSIZE(szFile)))
	{
		return FALSE;
	}
	__try
	{
		if (fPersistent)
		{
			GuidToStr(&PersistentTracingSessionGuid,szGuid);
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("Guid"), REG_SZ, szGuid,((DWORD)_tcslen(szGuid)+1) * sizeof(TCHAR));
			if (dwError != ERROR_SUCCESS) __leave;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("FileName"), REG_SZ,  szFile,((DWORD)_tcslen(szFile)+1) * sizeof(TCHAR));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 8;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("FileMax"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 1;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("Start"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 8;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("BufferSize"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 0;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("FlushTimer"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 0;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("MaximumBuffers"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 0;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("MinimumBuffers"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 1;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("ClockType"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 64;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("MaxFileSize"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 4864;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("LogFileMode"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 5;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("FileCounter"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;
			dwValue = 0;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"), 
				TEXT("Status"), REG_DWORD,&dwValue,sizeof(DWORD));
			if (dwError != ERROR_SUCCESS) __leave;

			for (int i = 0; i < ARRAYSIZE(GuidToTrace); i++)
			{
				TCHAR szRegKey[1024];
				TCHAR szGuid[40];
				GuidToStr(GuidToTrace+i,szGuid);
				_stprintf_s(szRegKey,TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff\\%s"),szGuid);
				dwValue = 1;
				dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, szRegKey, 
					TEXT("Enabled"), REG_DWORD,&dwValue,sizeof(DWORD));
				if (dwError != ERROR_SUCCESS) __leave;
				dwValue = 5;
				dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, szRegKey, 
					TEXT("EnableLevel"), REG_DWORD,&dwValue,sizeof(DWORD));
				if (dwError != ERROR_SUCCESS) __leave;
				dwValue = 0;
				dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, szRegKey, 
					TEXT("EnableProperty"), REG_DWORD,&dwValue,sizeof(DWORD));
				if (dwError != ERROR_SUCCESS) __leave;
				dwValue = 0;
				dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, szRegKey, 
					TEXT("Status"), REG_DWORD,&dwValue,sizeof(DWORD));
				if (dwError != ERROR_SUCCESS) __leave;
				qdwValue = 0;
				dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, szRegKey, 
					TEXT("MatchAllKeyword"), REG_QWORD,&qdwValue,sizeof(DWORD64));
				if (dwError != ERROR_SUCCESS) __leave;
				qdwValue = 0;
				dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, szRegKey, 
					TEXT("MatchAnyKeyword"), REG_QWORD,&qdwValue,sizeof(DWORD64));
				if (dwError != ERROR_SUCCESS) __leave;
			}
		}
		if (!StartLogging(fPersistent, 5))
		{
			dwError = GetLastError();
			__leave;
		}
		if (fPersistent || !IsPersistentLoggingEnabled())
		{
			if (!SaveSysDriver())
			{
				dwError = GetLastError();
				__leave;
			}
			if (!CreateDriverService(TEXT("\\SystemRoot\\system32\\drivers\\PINSniffDriver.sys")))
			{
				dwError = GetLastError();
				__leave;
			}
			if (!ChangeSmartCardReaderFilter(TRUE))
			{
				dwError = GetLastError();
				__leave;
			}
			if (!RestartSCReader())
			{
				dwError = GetLastError();
				__leave;
			}
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}


BOOL DisableLogging(BOOL fPersistent)
{
	BOOL fReturn = FALSE;
	LONG dwError = 0;
	BOOL fPersistentActive = IsPersistentLoggingEnabled();
	__try
	{
		if (fPersistent || !fPersistentActive)
		{
			if (!ChangeSmartCardReaderFilter(FALSE))
			{
				dwError = GetLastError();
				__leave;
			}
			if (!RestartSCReader())
			{
				dwError = GetLastError();
				__leave;
			}
			if (!RemoveDriverService())
			{
				dwError = GetLastError();
				__leave;
			}
		}

		if (!StopLogging(fPersistent))
		{
			dwError = GetLastError();
			__leave;
		}
		if (fPersistent)
		{
			fReturn = RegDelnode(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\PINSniff"));
			if (!fReturn) {
				dwError = GetLastError();
				__leave;
			}
		}
		if (fPersistent || !fPersistentActive)
		{
			if (!DeleteSysDriver())
			{
				dwError = GetLastError();
				__leave;
			}
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}
