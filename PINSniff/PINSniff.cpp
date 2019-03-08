// EIDLogManager.cpp : définit le point d'entrée pour l'application.
//
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <wmistr.h>
#include <evntrace.h>
#include <Shobjidl.h>
#include <Shlobj.h>
#include "resource.h"
#include "logging.h"

#pragma comment(lib,"Shell32")
#pragma comment(lib,"crypt32")
#pragma comment(lib,"Setupapi")



#define CLSCTX_INPROC_SERVER  1

// Variables globales :
HINSTANCE hInst;								// instance actuelle

INT_PTR CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
VOID LiveTracing(HWND hWnd);

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
typedef BOOL (WINAPI *LPFN_DISABLEWOW64FSREDIRECTION) (PVOID*);

VOID DisableWoW64FsRedirectionIfNeeded()
{
    BOOL bIsWow64 = FALSE;
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	LPFN_DISABLEWOW64FSREDIRECTION fnWow64DisableWow64FsRedirection;
	PVOID revert = NULL;
	
    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
        {
            //handle error
        }
		if (bIsWow64)
		{
			fnWow64DisableWow64FsRedirection =  (LPFN_DISABLEWOW64FSREDIRECTION) GetProcAddress(
					GetModuleHandle(TEXT("kernel32")),"Wow64DisableWow64FsRedirection");
			if (NULL != fnWow64DisableWow64FsRedirection)
			{
				fnWow64DisableWow64FsRedirection(&revert);
			}
		}
    }
}

#define DisplayError(status) DisplayErrorEx (status, __FILE__,__LINE__);
/**
 *  Display a messagebox giving an error code
 */
void DisplayErrorEx(__in DWORD status, __in LPCSTR szFile, __in DWORD dwLine)
{
	LPSTR Error;
	// system error message
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,status,0,(LPSTR)&Error,0,NULL);
	fprintf(stderr,"%s(%d) 0x%08X - %s",szFile, dwLine, status,Error);
	LocalFree(Error);
}

typedef struct _WPP_DATA
{
	DWORD dwSequenceNum;
	GUID MessageGuid;
	DWORD dwTest1;
	DWORD dwTest2;
	DWORD dwTest3;
	DWORD dwTest4;
	DWORD dwTest5;
} WPP_DATA, *PWPP_DATA;


VOID PrintAPDU(PEVENT_TRACE pEvent, PSTR szAPDU)
{
	SYSTEMTIME st;
	FILETIME ft;
			
	if (pEvent->Header.TimeStamp.HighPart != 0 && pEvent->Header.TimeStamp.LowPart != 0)
	{
		FileTimeToLocalFileTime((FILETIME*)&(pEvent->Header.TimeStamp), &ft);
		FileTimeToSystemTime(&ft, &st);
	}
	else
	{
		GetSystemTime(&st);
	}
	printf("%04d-%02d-%02d %02d:%02d:%02d,",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
	printf(szAPDU);
	printf("\r\n"); 
}

#define PREFIX_VERIFY_PIN "00 20 00 80 "
#define PREFIX_RESET "Reset"
BOOL fPINVerifyInProgress = FALSE;
VOID WINAPI ProcessEvents(PEVENT_TRACE pEvent)
{
	// Is this the first event of the session? The event is available only if
	// you are consuming events from a log file, not a real-time session.
	if (pEvent->Header.Class.Type == EVENT_TRACE_TYPE_INFO)
    {
        ; // Skip this event.
    }
    else
    {
		//Process the event. The pEvent->MofData member is a pointer to 
		//the event specific data, if it exists.
		if (pEvent->MofLength)
		{
			DWORD dwOffset;
			for(dwOffset = 0; dwOffset < pEvent->MofLength; dwOffset++) 
			{
				if (memcmp((PBYTE) pEvent->MofData + dwOffset, "APDU:",5) == 0) {
					dwOffset += 5;
					break;
				}
			}
			if (dwOffset >= pEvent->MofLength)
				return;

			PSTR szAPDU = (PSTR) pEvent->MofData + dwOffset;
			if (strncmp(PREFIX_VERIFY_PIN, szAPDU, strlen(PREFIX_VERIFY_PIN)) == 0)
			{
				fPINVerifyInProgress = true;
				PrintAPDU(pEvent, szAPDU);
				printf("PIN:");
				for (dwOffset = (DWORD) strlen(PREFIX_VERIFY_PIN) + 3; dwOffset < strlen(szAPDU); dwOffset += 3)
				{
					CHAR szValue[4];
					strncpy_s(szValue, szAPDU + dwOffset, 2);
					int number = (int)strtol(szValue, NULL, 16);
					printf("%c", number);
				}
				printf("\r\n");
			} 
			else if (fPINVerifyInProgress)
			{
				PrintAPDU(pEvent, szAPDU);
				fPINVerifyInProgress = FALSE;
				if (strcmp(szAPDU, "90 00 ") == 0)
				{
					printf("Sucess\r\n");
				}
				else
				{
					printf("Failure\r\n");
				}
			}
			else if (strncmp(PREFIX_RESET, szAPDU, strlen(PREFIX_RESET)) == 0)
			{
				PrintAPDU(pEvent, szAPDU);
			}
		}
		else
		{
			printf("-\r\n");
		}
	}
}

void ExportOneTraceFile(PSTR szTraceFile)
{
	TRACEHANDLE handle = NULL;
	ULONG rc;
	EVENT_TRACE_LOGFILEA trace;
	CHAR szTraceFileExpanded[MAX_PATH+1];
	if (!ExpandEnvironmentStringsA(szTraceFile, szTraceFileExpanded, ARRAYSIZE(szTraceFileExpanded)))
	{
		return;
	}

	memset(&trace,0, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = "PINSniff"; 
	//trace.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	trace.LogFileName = szTraceFileExpanded;
	trace.EventCallback = (PEVENT_CALLBACK) (ProcessEvents);
	handle = OpenTraceA(&trace);
	if ((TRACEHANDLE)INVALID_HANDLE_VALUE == handle)
	{
		// Handle error as appropriate for your application.
	}
	else
	{
		FILETIME now, start;
		SYSTEMTIME sysNow, sysstart;
		GetLocalTime(&sysNow);
		SystemTimeToFileTime(&sysNow, &now);
		memcpy(&sysstart, &sysNow, sizeof(SYSTEMTIME));
		sysstart.wYear -= 1;
		SystemTimeToFileTime(&sysstart, &start);
		printf("================================================\r\n");
		printf("%s\r\n", szTraceFileExpanded);
		printf("================================================\r\n");
		rc = ProcessTrace(&handle, 1, 0, 0);
		if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED)
		{
			if (rc ==  0x00001069)
			{
			}
			else
			{
			}
		}
		CloseTrace(handle);
	}
}

void ProcessPersistentLog()
{
    __try
	{
		ExportOneTraceFile(("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl"));
		ExportOneTraceFile(("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl.001"));
		ExportOneTraceFile(("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl.002"));
		ExportOneTraceFile(("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl.003"));
		ExportOneTraceFile(("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl.004"));
		ExportOneTraceFile(("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl.005"));
		ExportOneTraceFile(("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl.006"));
		ExportOneTraceFile(("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl.007"));
		ExportOneTraceFile(("%systemroot%\\system32\\LogFiles\\WMI\\PINSniff.etl.008"));
	}
	__finally
	{
	}
}

void ProcessLiveLog()
{
	ULONG rc;
	EVENT_TRACE_LOGFILE trace;
	TRACEHANDLE handle;

	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = TEXT("PINSniffLive"); 
	trace.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	trace.EventCallback = (PEVENT_CALLBACK) (ProcessEvents);

	handle = OpenTrace(&trace);
	if ((TRACEHANDLE)INVALID_HANDLE_VALUE == handle)
	{
		// Handle error as appropriate for your application.
		fprintf(stderr, "OpenTrace failed\r\n");
		DisplayError(GetLastError());
	}
	else
	{
		printf("Monitoring Active\r\n");
		rc = ProcessTrace(&handle, 1, 0, 0);
		if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED)
		{
			if (rc ==  0x00001069)
			{
				printf("Tracing was not started\r\n");
			}
			else
			{
				DisplayError(rc);
				printf("ProcessTrace failed\r\n");
			}
		
		}
		printf("ProcessTrace ended\r\n");
		rc = CloseTrace(handle);
		handle = NULL;
	}
}


BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
		case CTRL_CLOSE_EVENT:
		case CTRL_C_EVENT:
			if (!DisableLogging(FALSE))
			{
				printf("error while disabling Live logging\r\n");
				DisplayError(GetLastError());
				return -1;
			}
			printf("Live logging disabled\r\n");
		break;
	}
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	DisableWoW64FsRedirectionIfNeeded();
	for(int i = 1; i < argc; i++)
	{
		if (_wcsicmp(argv[i], L"--enable-persistant") == 0)
		{
			if (!EnableLogging(TRUE))
			{
				DisplayError(GetLastError());
				return -1;
			}
			printf("Persistant logging enabled\r\n");
			return 0;
		}
		if (_wcsicmp(argv[i], L"--disable-persistant") == 0)
		{
			if (!DisableLogging(TRUE))
			{
				DisplayError(GetLastError());
				return -1;
			}
			printf("Persistant logging disabled\r\n");
			return 0;
		}
		if (_wcsicmp(argv[i], L"--kill") == 0)
		{
			if (!DisableLogging(FALSE))
			{
				DisplayError(GetLastError());
				return -1;
			}
			printf("Live logging disabled\r\n");
			return 0;
		}
	}
	if (IsPersistentLoggingEnabled())
	{
		printf("Reading persistent logs\r\n");
		ProcessPersistentLog();
	}
	else
	{
		printf("Using live mode\r\n");
		if (!EnableLogging(FALSE))
		{
			printf("Unable to enable logging\r\n");
			DisplayError(GetLastError());
			return -1;
		}
		SetConsoleCtrlHandler(CtrlHandler, TRUE);
		ProcessLiveLog();
	}
	return 0;
}
