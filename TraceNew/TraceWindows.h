#pragma once

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ Windows (HRESULT)
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
inline const _error_category& windows_category() 
{
    // ��������� ������ Windows
    return std::system_category(); 
}
#else
class _windows_category : public _error_category
{
    // �������� ��������� �� ������
    public: virtual std::string message(int code) const 
    {
		// ������� ��������� �������
		std::string msg = "<UNKNOWN>"; PSTR szBuffer = nullptr;  

		// ������� ����� ����������
		DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS; 

		// �������� ��������� �� ������
		if (::FormatMessageA(flags, 0, code, LANG_NEUTRAL, (PSTR)&szBuffer, 0, nullptr))
		{
			// ���������� ���������� �����
			msg = szBuffer; ::LocalFree(szBuffer); 
		}
        return msg; 
    }
};
inline const _error_category& windows_category() 
{
    // ��������� ������ Windows
    static _windows_category windows_category; return windows_category; 
}
#endif

///////////////////////////////////////////////////////////////////////////////
// �������� ������ HRESULT
///////////////////////////////////////////////////////////////////////////////
class hresult_error : public _error_code
{
    // �����������
    public: hresult_error(HRESULT code) 
        
        // ��������� ��� ������
        : _error_code((int)code, windows_category()) {}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������ Windows
///////////////////////////////////////////////////////////////////////////////
class windows_error : public hresult_error
{
    // �����������
    public: windows_error(DWORD code) 
        
        // ��������� ��� ������
        : hresult_error(HRESULT_FROM_WIN32(code)) {}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������ Native API
///////////////////////////////////////////////////////////////////////////////
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

// �������� ������ Native API
class native_error : public windows_error
{
    // �����������
    public: native_error(NTSTATUS status) 
        
        // ��������� ��� ������
        : windows_error(WINERROR_FROM_NTSTATUS(status)) {}
};

///////////////////////////////////////////////////////////////////////////////
// ���������� Windows
///////////////////////////////////////////////////////////////////////////////
class windows_exception : public system_exception
{
    // �����������
    public: windows_exception(const hresult_error& code, const char* szFile, int line)

        // ��������� ���������� ���������
        : system_exception(code, szFile, line) {}

    // ��������� ����������
    public: virtual __noreturn void raise() const { trace(); throw *this; }

    // ��������� ��� ��������� ������
    public: virtual void SetLastError() const { ::SetLastError(code().value()); }
};

///////////////////////////////////////////////////////////////////////////////
// ������� ������� Windows
///////////////////////////////////////////////////////////////////////////////
inline bool IsWindowsService()
{
    // �������� ��������� ��������
    HANDLE hProcess = ::GetCurrentProcess(); HANDLE hToken = nullptr; 

    // ������� �������� ��������
    if (!::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return false; 

    // �������� ������ ��� �������������� ������
    DWORD sessionID; DWORD cb = sizeof(sessionID); 

    // �������� ������������� ������
    if (!::GetTokenInformation(hToken, TokenSessionId, &sessionID, cb, &cb)) cb = 0; 

    // ������� �������� ��������
    ::CloseHandle(hToken); return (cb > 0) && (sessionID == 0); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� ���������
///////////////////////////////////////////////////////////////////////////////
namespace trace {
inline std::string GetServiceEnvironmentVariable(const char* szName)
{
    // ���������������� ����������
    std::string value; HKEY hKey; DWORD cbValue = 0; 

    // ������� ��� ������� �������
    PCSTR szRegistryKey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"; 

    // ������� ������ �������
    LSTATUS status = ::RegOpenKeyExA(HKEY_LOCAL_MACHINE, szRegistryKey, 0, KEY_QUERY_VALUE, &hKey); 

    // ��������� ���������� ������
    if (status != ERROR_SUCCESS) return value;  

    // ���������� ������ ��������
    status = ::RegQueryValueExA(hKey, szName, nullptr, nullptr, nullptr, &cbValue); 

    // �������� ����� ���������� �������
    if (status == ERROR_SUCCESS) { value.resize((size_t)cbValue + 1);  

        // �������� ��������
        status = ::RegQueryValueExA(hKey, szName, nullptr, nullptr, (PBYTE)&value[0], &cbValue); 

        // ���������� �������������� ������ ��������
        value.resize(status == ERROR_SUCCESS ? strlen(value.c_str()) : 0); 
    }
    // ������� ������ �������
    ::RegCloseKey(hKey); return value;
}

inline std::string GetEnvironmentVariable(const char* szName)
{
    // �������� ���������� ���������
    if (!IsWindowsService()) return GetPosixEnvironmentVariable(szName); 

    // �������� ���������� ���������
    std::string value = GetServiceEnvironmentVariable(szName); 

    // ���������� ���������� ���������
    ::SetEnvironmentVariableA(szName, value.empty() ? nullptr : value.c_str()); return value;
}
}
