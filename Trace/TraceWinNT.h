#pragma once
#include "ntapi.h"

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки Native API
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline DWORD WINERROR_FROM_NTSTATUS(NTSTATUS status)
{
    // проверить наличие ошибки
    if (!FAILED(status)) return ERROR_SUCCESS; 

    // указать прототип функции
	typedef DWORD (WINAPI* PfnRtlNtStatusToDosError)(NTSTATUS);

	// определить адрес модуля
    HMODULE hModule = ::GetModuleHandleW(L"ntdll.dll");

	// получить адрес функции
	FARPROC pfn = ::GetProcAddress(hModule, "RtlNtStatusToDosError");
																			
	// преобразовать код ошибки 
	return (*(PfnRtlNtStatusToDosError)pfn)(status);
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок NTSTATUS
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

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_NTSTATUS(LEVEL, STATUS)        (NTSTATUS, STATUS, NT_ERROR, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_NTSTATUS_PRE(LEVEL, STATUS)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_NTSTATUS_ENABLED(LEVEL, STATUS)   NT_ERROR(WPP_VAR(__LINE__))

// Проверка наличия ошибки
#define WPP_TRACELEVEL_NTSTATUS_POST(LEVEL, STATUS)                         \
    ; if (WPP_TRACELEVEL_NTSTATUS_ENABLED(LEVEL, STATUS)) {                 \
         WPP_TRACELEVEL_NTSTATUS_RAISE(__FILE__, __LINE__)                  \
    }}

///////////////////////////////////////////////////////////////////////////////
// Определение трассировки
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
