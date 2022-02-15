#pragma once

///////////////////////////////////////////////////////////////////////////////
// Категория ошибок Windows (HRESULT)
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
inline const _error_category& windows_category() 
{
    // категория ошибок Windows
    return std::system_category(); 
}
#else
class _windows_category : public _error_category
{
    // получить сообщение об ошибке
    public: virtual std::string message(int code) const 
    {
		// указать начальные условия
		std::string msg = "<UNKNOWN>"; PSTR szBuffer = nullptr;  

		// указать режим выполнения
		DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS; 

		// получить сообщение об ошибке
		if (::FormatMessageA(flags, 0, code, LANG_NEUTRAL, (PSTR)&szBuffer, 0, nullptr))
		{
			// освободить выделенный буфер
			msg = szBuffer; ::LocalFree(szBuffer); 
		}
        return msg; 
    }
};
inline const _error_category& windows_category() 
{
    // категория ошибок Windows
    static _windows_category windows_category; return windows_category; 
}
#endif

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки HRESULT
///////////////////////////////////////////////////////////////////////////////
class hresult_error : public _error_code
{
    // конструктор
    public: hresult_error(HRESULT code) 
        
        // сохранить код ошибки
        : _error_code((int)code, windows_category()) {}
};

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки Windows
///////////////////////////////////////////////////////////////////////////////
class windows_error : public hresult_error
{
    // конструктор
    public: windows_error(DWORD code) 
        
        // сохранить код ошибки
        : hresult_error(HRESULT_FROM_WIN32(code)) {}
};

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки Native API
///////////////////////////////////////////////////////////////////////////////
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

// Описание ошибки Native API
class native_error : public windows_error
{
    // конструктор
    public: native_error(NTSTATUS status) 
        
        // сохранить код ошибки
        : windows_error(WINERROR_FROM_NTSTATUS(status)) {}
};

///////////////////////////////////////////////////////////////////////////////
// Исключение Windows
///////////////////////////////////////////////////////////////////////////////
class windows_exception : public system_exception
{
    // конструктор
    public: windows_exception(const hresult_error& code, const char* szFile, int line)

        // сохранить переданные параметры
        : system_exception(code, szFile, line) {}

    // выбросить исключение
    public: virtual __noreturn void raise() const { trace(); throw *this; }

    // сохранить код последней ошибки
    public: virtual void SetLastError() const { ::SetLastError(code().value()); }
};

///////////////////////////////////////////////////////////////////////////////
// Признак сервиса Windows
///////////////////////////////////////////////////////////////////////////////
inline bool IsWindowsService()
{
    // получить описатель процесса
    HANDLE hProcess = ::GetCurrentProcess(); HANDLE hToken = nullptr; 

    // открыть контекст процесса
    if (!::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return false; 

    // выделить памчть для идентификатора сеанса
    DWORD sessionID; DWORD cb = sizeof(sessionID); 

    // получить идентификатор сеанса
    if (!::GetTokenInformation(hToken, TokenSessionId, &sessionID, cb, &cb)) cb = 0; 

    // закрыть контекст процесса
    ::CloseHandle(hToken); return (cb > 0) && (sessionID == 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Получить переменную окружения
///////////////////////////////////////////////////////////////////////////////
namespace trace {
inline std::string GetServiceEnvironmentVariable(const char* szName)
{
    // инициализировать переменные
    std::string value; HKEY hKey; DWORD cbValue = 0; 

    // указать имя раздела реестра
    PCSTR szRegistryKey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"; 

    // открыть раздел реестра
    LSTATUS status = ::RegOpenKeyExA(HKEY_LOCAL_MACHINE, szRegistryKey, 0, KEY_QUERY_VALUE, &hKey); 

    // проверить отсутствие ошибок
    if (status != ERROR_SUCCESS) return value;  

    // определить размер значения
    status = ::RegQueryValueExA(hKey, szName, nullptr, nullptr, nullptr, &cbValue); 

    // выделить буфер требуемого размера
    if (status == ERROR_SUCCESS) { value.resize((size_t)cbValue + 1);  

        // получить значение
        status = ::RegQueryValueExA(hKey, szName, nullptr, nullptr, (PBYTE)&value[0], &cbValue); 

        // установить действительный размер значения
        value.resize(status == ERROR_SUCCESS ? strlen(value.c_str()) : 0); 
    }
    // закрыть раздел реестра
    ::RegCloseKey(hKey); return value;
}

inline std::string GetEnvironmentVariable(const char* szName)
{
    // получить переменную окружения
    if (!IsWindowsService()) return GetPosixEnvironmentVariable(szName); 

    // получить переменную окружения
    std::string value = GetServiceEnvironmentVariable(szName); 

    // установить переменную окружения
    ::SetEnvironmentVariableA(szName, value.empty() ? nullptr : value.c_str()); return value;
}
}
