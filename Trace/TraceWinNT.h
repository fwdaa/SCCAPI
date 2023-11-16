#pragma once
#include "ntapi.h"

///////////////////////////////////////////////////////////////////////////////
// �������� ������ Native API
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline DWORD WINERROR_FROM_NTSTATUS(NTSTATUS status)
{
    // ��������� ������� ������
    if (!FAILED(status)) return ERROR_SUCCESS; 

    // ������� �������� �������
	typedef DWORD (WINAPI* PfnRtlNtStatusToDosError)(NTSTATUS);

	// ���������� ����� ������
    HMODULE hModule = ::GetModuleHandleW(L"ntdll.dll");

	// �������� ����� �������
	FARPROC pfn = ::GetProcAddress(hModule, "RtlNtStatusToDosError");
																			
	// ������������� ��� ������ 
	return (*(PfnRtlNtStatusToDosError)pfn)(status);
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ NTSTATUS
///////////////////////////////////////////////////////////////////////////////
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_NTSTATUS_RAISE(FILE, LINE)                           \
    windows_error(HRESULT_FROM_NT(WPP_VAR(LINE))).trace(FILE, LINE);        \
    throw gcnew System::ComponentModel::Win32Exception(                     \
        HRESULT_FROM_WIN32(WINERROR_FROM_NTSTATUS(WPP_VAR(LINE))).value()    \
    );  
#elif !defined _NTDDK_
#define WPP_TRACELEVEL_NTSTATUS_RAISE(FILE, LINE)                           \
    windows_error(HRESULT_FROM_NT(WPP_VAR(LINE))).raise(FILE, LINE);
#else 
#define WPP_TRACELEVEL_NTSTATUS_RAISE(FILE, LINE)                           \
    ExRaiseStatus(WPP_VAR(LINE));
#endif 

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_NTSTATUS(LEVEL, STATUS)        (NTSTATUS, STATUS, NT_ERROR, LEVEL)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_NTSTATUS_PRE(LEVEL, STATUS)       

// �������� ������� �����������
#define WPP_TRACELEVEL_NTSTATUS_ENABLED(LEVEL, STATUS)   NT_ERROR(WPP_VAR(__LINE__))

// �������� ������� ������
#define WPP_TRACELEVEL_NTSTATUS_POST(LEVEL, STATUS)                         \
    ; if (WPP_TRACELEVEL_NTSTATUS_ENABLED(LEVEL, STATUS)) {                 \
         WPP_TRACELEVEL_NTSTATUS_RAISE(__FILE__, __LINE__)                  \
    }}

///////////////////////////////////////////////////////////////////////////////
// ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_NTSTATUS_LOGGER(LEVEL, STATUS)    WppGetLogger(),
#else 
#define AE_CHECK_NTSTATUS(STATUS)                                                                                \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_NTSTATUS(TRACE_LEVEL_ERROR, STATUS), "ERROR %!STATUS!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_NTSTATUS_PRE(TRACE_LEVEL_ERROR, STATUS)                                                       \
    (void)((                                                                                                     \
        WPP_TRACELEVEL_NTSTATUS_ENABLED(TRACE_LEVEL_ERROR, STATUS)                                               \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!STATUS!", WPP_VAR(__LINE__))), 1 : 0                                    \
    ))                                                                                                           \
    WPP_TRACELEVEL_NTSTATUS_POST(TRACE_LEVEL_ERROR, STATUS)
#endif 
