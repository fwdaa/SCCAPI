#pragma once
#include "TraceWinNT.h"

#if !defined _NTDDK_
#include "TraceError.h"

///////////////////////////////////////////////////////////////////////////////
// Определение отсутствия возврата из функции
///////////////////////////////////////////////////////////////////////////////
#if defined __GNUC__
#define _NORETURN	__attribute__((noreturn))
#elif defined _MSC_VER
#define _NORETURN	__declspec(noreturn)
#else 
#define _NORETURN	[[noreturn]]
#endif 

///////////////////////////////////////////////////////////////////////////////
// Категория ошибок Windows (NTSTATUS и подсистема Win32)
///////////////////////////////////////////////////////////////////////////////
class _windows_category : public std::error_category
{
    // конструктор
    public: _windows_category(LANGID langID = 0)

        // сохранить переданные параметры 
        : _langID(langID) {} private: LANGID _langID;  
    
    // имя категории ошибки 
    public: virtual const char* name() const noexcept { return "system"; }

    // получить сообщение об ошибке
    public: virtual std::string message(int code) const; 
};

inline const std::error_category& windows_category() 
{
    // категория ошибок Windows
    static _windows_category category; return category; 
}

inline std::string _windows_category::message(int code) const 
{
    // указать режим выполнения 
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS; 

    // для ошибок NTSTATUS
    if (HRESULT_FACILITY(code) == FACILITY_NT_BIT)
    {
        // извлечь NTSTATUS
        NTSTATUS status = code & ~FACILITY_NT_BIT; 

	    // указать режим выполнения
		PSTR szBuffer = nullptr; flags |= FORMAT_MESSAGE_FROM_HMODULE; 

        // указать модуль для поиска 
        HMODULE hModule = ::GetModuleHandleW(L"ntdll.dll"); 

		// получить сообщение об ошибке
		if (::FormatMessageA(flags, hModule, status, _langID, (PSTR)&szBuffer, 0, nullptr))
		{
		    // вернуть сообщение об ошибке 
			std::string msg(szBuffer); ::LocalFree(szBuffer); return msg; 
		}
        // преобразовать код ошибки 
        code = (int)WINERROR_FROM_NTSTATUS(status); flags &= ~FORMAT_MESSAGE_FROM_HMODULE;
    }
    // для ошибки подсистемы Win32
    if (HRESULT_FACILITY(code) == FACILITY_WIN32) code = HRESULT_CODE(code);
    {
        // указать наличие системной ошибки 
        PSTR szBuffer = nullptr; flags |= FORMAT_MESSAGE_FROM_SYSTEM; 

        // получить сообщение об ошибке
	    if (::FormatMessageA(flags, NULL, code, _langID, (PSTR)&szBuffer, 0, nullptr))
	    {
            // вернуть сообщение об ошибке 
		    std::string msg(szBuffer); ::LocalFree(szBuffer); return msg; 
	    }
    }
    return "<UNKNOWN>"; 
}

///////////////////////////////////////////////////////////////////////////////
// Категория ошибок подсистемы Win32
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && _MSC_VER < 1600
namespace std {
inline const std::error_category& system_category() 
{
    // категория ошибок Windows
    return windows_category(); 
}
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Исключение Windows
///////////////////////////////////////////////////////////////////////////////
class windows_error : public trace::system_error<>
{
    // конструктор
    public: windows_error(DWORD code)

        // сохранить переданные параметры
        : trace::system_error<>((int)code, windows_category()) {}

    // выбросить исключение
    public: virtual _NORETURN void raise(const char* szFile, int line) const 
    { 
        // выбросить исключение
        trace(szFile, line); throw *this; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок Windows 
///////////////////////////////////////////////////////////////////////////////
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_WINERROR_RAISE(FILE, LINE)                           \
    windows_error(HRESULT_FROM_WIN32(WPP_VAR(LINE))).trace(FILE, LINE);     \
    throw gcnew System::ComponentModel::Win32Exception(                     \
        HRESULT_FROM_WIN32(WPP_VAR(LINE))                                   \
    );
#else
#define WPP_TRACELEVEL_WINERROR_RAISE(FILE, LINE)                           \
    windows_error(HRESULT_FROM_WIN32(WPP_VAR(LINE))).raise(FILE, LINE);
#endif 

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_WINERROR(LEVEL, ERROR)    (DWORD, ERROR, WPP_CAST_BOOL, LEVEL)

// Сохранение кода ошибки
#define WPP_TRACELEVEL_WINERROR_PRE(LEVEL, ERROR)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_WINERROR_ENABLED(LEVEL, ERROR)   WPP_VAR(__LINE__)

// Проверка наличия ошибки
#define WPP_TRACELEVEL_WINERROR_POST(LEVEL, ERROR)                          \
    ; if (WPP_TRACELEVEL_WINERROR_ENABLED(LEVEL, ERROR)) {                  \
         WPP_TRACELEVEL_WINERROR_RAISE(__FILE__, __LINE__)                  \
    }}

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок WinAPI
///////////////////////////////////////////////////////////////////////////////

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_WINAPI(LEVEL, RET)        (DWORD, (RET) ? ERROR_SUCCESS : ::GetLastError(), WPP_CAST_BOOL, LEVEL)

// Отсутствие дополнительных действий
#define WPP_TRACELEVEL_WINAPI_PRE(LEVEL, RET)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_WINAPI_ENABLED(LEVEL, RET)       WPP_VAR(__LINE__)

// Проверка наличия ошибки
#define WPP_TRACELEVEL_WINAPI_POST(LEVEL, RET)                              \
    ; if (WPP_TRACELEVEL_WINAPI_ENABLED(LEVEL, RET)) {                      \
         WPP_TRACELEVEL_WINERROR_RAISE(__FILE__, __LINE__)                  \
    }}

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок WinSock
///////////////////////////////////////////////////////////////////////////////

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_WINSOCK(LEVEL, RET)       (DWORD, ((RET) >= 0) ? ERROR_SUCCESS : ::WSAGetLastError(), WPP_CAST_BOOL, LEVEL)

// Отсутствие дополнительных действий
#define WPP_TRACELEVEL_WINSOCK_PRE(LEVEL, RET)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_WINSOCK_ENABLED(LEVEL, RET)      WPP_VAR(__LINE__)

// Проверка наличия ошибки
#define WPP_TRACELEVEL_WINSOCK_POST(LEVEL, RET)                            \
    ; if (WPP_TRACELEVEL_WINSOCK_ENABLED(LEVEL, RET)) {                    \
         WPP_TRACELEVEL_WINERROR_RAISE(__FILE__, __LINE__)                 \
    }}

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок HRESULT
///////////////////////////////////////////////////////////////////////////////
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_HRESULT_RAISE(FILE, LINE)                            \
    windows_error(WPP_VAR(LINE)).trace(FILE, LINE);                         \
    throw gcnew System::ComponentModel::Win32Exception(WPP_VAR(LINE));  
#else
#define WPP_TRACELEVEL_HRESULT_RAISE(FILE, LINE)                            \
    windows_error(WPP_VAR(LINE)).raise(FILE, LINE);
#endif 

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_HRESULT(LEVEL, HR)        (HRESULT, HR, FAILED, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_HRESULT_PRE(LEVEL, HR)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)   		FAILED(WPP_VAR(__LINE__))

// Проверка наличия ошибки
#define WPP_TRACELEVEL_HRESULT_POST(LEVEL, HR)                              \
    ; if (WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)) {                      \
         WPP_TRACELEVEL_HRESULT_RAISE(__FILE__, __LINE__)                   \
    }}

///////////////////////////////////////////////////////////////////////////////
// Определение трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_WINERROR_LOGGER(LEVEL, ERROR)    WppGetLogger(),
#define WPP_TRACELEVEL_WINAPI_LOGGER(LEVEL,   RET  )    WppGetLogger(),
#define WPP_TRACELEVEL_WINSOCK_LOGGER(LEVEL,  RET  )    WppGetLogger(),
#define WPP_TRACELEVEL_HRESULT_LOGGER(LEVEL,  HR   )    WppGetLogger(),
#else 
#define AE_CHECK_WINERROR(ERROR)                                                                                    \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_WINERROR(TRACE_LEVEL_ERROR, ERROR), "ERROR %!WINERROR!", WPP_VAR(__LINE__))    \
    WPP_TRACELEVEL_WINERROR_PRE(TRACE_LEVEL_ERROR, ERROR)                                                           \
    (void)((                                                                                                        \
        WPP_TRACELEVEL_WINERROR_ENABLED(TRACE_LEVEL_ERROR, ERROR)                                                   \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!WINERROR!", WPP_VAR(__LINE__))), 1 : 0                                     \
    ))                                                                                                              \
    WPP_TRACELEVEL_WINERROR_POST(TRACE_LEVEL_ERROR, ERROR)                                      

#define AE_CHECK_WINAPI(RET)                                                                                        \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_WINAPI(TRACE_LEVEL_ERROR, RET), "ERROR %!WINERROR!", WPP_VAR(__LINE__))        \
    WPP_TRACELEVEL_WINAPI_PRE(TRACE_LEVEL_ERROR, RET)                                                               \
    (void)((                                                                                                        \
        WPP_TRACELEVEL_WINAPI_ENABLED(TRACE_LEVEL_ERROR, RET)                                                       \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!WINERROR!", WPP_VAR(__LINE__))), 1 : 0                                     \
    ))                                                                                                              \
    WPP_TRACELEVEL_WINAPI_POST(TRACE_LEVEL_ERROR, RET)                                      

#define AE_CHECK_WINSOCK(RET)                                                                                 	    \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_WINSOCK(TRACE_LEVEL_ERROR, RET), "ERROR %!WINERROR!", WPP_VAR(__LINE__))       \
    WPP_TRACELEVEL_WINSOCK_PRE(TRACE_LEVEL_ERROR, RET)                                                              \
    (void)((                                                                                                        \
        WPP_TRACELEVEL_WINSOCK_ENABLED(TRACE_LEVEL_ERROR, RET)                                                      \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!WINERROR!", WPP_VAR(__LINE__)), 1 : 0                                	    \
    ))                                                                                                              \
    WPP_TRACELEVEL_WINSOCK_POST(TRACE_LEVEL_ERROR, RET)                                      

#define AE_CHECK_HRESULT(HR)                                                                                        \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_HRESULT(TRACE_LEVEL_ERROR, HR), "ERROR %!HRESULT!", WPP_VAR(__LINE__))         \
    WPP_TRACELEVEL_HRESULT_PRE(TRACE_LEVEL_ERROR, HR)                                                               \
    (void)((                                                                                                        \
        WPP_TRACELEVEL_HRESULT_ENABLED(TRACE_LEVEL_ERROR, HR)                                                       \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!HRESULT!", WPP_VAR(__LINE__))), 1 : 0                                      \
    ))                                                                                                              \
    WPP_TRACELEVEL_HRESULT_POST(TRACE_LEVEL_ERROR, HR)                                  

#endif 

///////////////////////////////////////////////////////////////////////////////
// Отмена действия макросов
///////////////////////////////////////////////////////////////////////////////
#undef _NORETURN
#endif 
