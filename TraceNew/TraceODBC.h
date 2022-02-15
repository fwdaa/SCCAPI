#pragma once

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ ODBC
///////////////////////////////////////////////////////////////////////////////
class odbc_error_category : public trace::error_category<SQLRETURN>
{
	// �������� ������� SQLGetDiagRecW
	private: typedef SQLRETURN (SQL_API* PFNSQLGETDIAGRECW)(
    	SQLSMALLINT, SQLHANDLE, SQLSMALLINT, SQLWCHAR*, 
		SQLINTEGER*, SQLWCHAR*, SQLSMALLINT, SQLSMALLINT*
	);
	// ����� ������� SQLGetDiagRecW
    private: PFNSQLGETDIAGRECW _pfnGetDiagRecW; 

	// �����������
	public: odbc_error_category(HMODULE hModule) 
	{
        // �������� ����� ������������ �������
	    if (!hModule) _pfnGetDiagRecW = (PFNSQLGETDIAGRECW)::SQLGetDiagRecW;

        // �������� ����� ������������ �������
    	else _pfnGetDiagRecW = (PFNSQLGETDIAGRECW)::GetProcAddress(hModule, "SQLGetDiagRecW");
	}
    // �������� ��������� �� ������
    public: virtual std::string message(SQLRETURN status) const; 

    // �������� �������������� ���������� �� ������
    public: void trace(SQLHANDLE handle, SQLSMALLINT type) const; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������ ODBC
///////////////////////////////////////////////////////////////////////////////
class odbc_error : public trace::error_code<SQLRETURN>
{
    // �����������
    public: odbc_error(const odbc_error_category& category, SQLRETURN status) 
        
        // ��������� ���������� ���������
        : trace::error_code<SQLRETURN>(status, category) {} 

	// ������� ������� ������
	public: operator const void* () const 
	{ 
		// ������� ������� ������
		return  (!SQL_SUCCEEDED(value())) ? this : (const void*)0; 
	}
    // ������������� �������� ������
    public: std::string name() const
    {	
    	// ��� ������
	   	switch (value())
        {
	    // �������� �������� �������
	    case SQL_INVALID_HANDLE		 : return "SQL_INVALID_HANDLE"		; 
		case SQL_ERROR				 : return "SQL_ERROR"				; 
		case SQL_SUCCESS			 : return "SQL_SUCCESS"				;  
		case SQL_SUCCESS_WITH_INFO	 : return "SQL_SUCCESS_WITH_INFO"	; 
		case SQL_STILL_EXECUTING	 : return "SQL_STILL_EXECUTING"		; 
		case SQL_NEED_DATA			 : return "SQL_NEED_DATA"			; 
		case SQL_NO_DATA			 : return "SQL_NO_DATA"				; 
		case SQL_PARAM_DATA_AVAILABLE: return "SQL_PARAM_DATA_AVAILABLE"; 
    	}
        // ��������������� ��� ������
        char str[16]; trace::snprintf(str, sizeof(str), "%hd", value()); return str; 
	}
}; 
inline std::string odbc_error_category::message(SQLRETURN status) const
{
    // �������� ��������� �� ������
	return odbc_error(*this, status).name(); 
} 
///////////////////////////////////////////////////////////////////////////////
// ���������� ODBC
///////////////////////////////////////////////////////////////////////////////
class odbc_exception : public trace::exception<SQLRETURN>
{	
    // ��� �������� ������
    private: typedef trace::exception<SQLRETURN> base_type; 

	// ��������� ������� � ��� ���
	private: SQLHANDLE _handle; SQLSMALLINT _type; 

    // �����������
    public: odbc_exception(const odbc_error& error, 
		SQLHANDLE handle, SQLSMALLINT type, const char* szFile, int line)

        // ��������� ���������� ���������
        : base_type(error, szFile, line), _handle(handle), _type(type) {}

	// �������� �������������� ���������� �� ������
    public: virtual void trace() const
	{
		// ��������� ������� �������������� ����������
		if (value() != SQL_ERROR && value() != SQL_SUCCESS_WITH_INFO) return; 

		// �������� �������������� ���������� �� ������
		((const odbc_error_category&)code().category()).trace(_handle, _type); 
	} 
    // ��������� ����������
    public: virtual __noreturn void raise() const { trace(); throw *this; }
};

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (843BC251, CF10, 4C7B, B989, 9FD4A1244B08)
#include "TraceODBC.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� �� ������
///////////////////////////////////////////////////////////////////////////////
inline void odbc_error_category::trace(SQLHANDLE handle, SQLSMALLINT type) const
{
	// �������� ����� ��� ��������� ����� ��������
	SQLWCHAR state[6]; SQLINTEGER code; SQLSMALLINT cch;

   	// ���������� ������ ������ ��� ���������
   	SQLRETURN status = (*_pfnGetDiagRecW)(type, handle, 1, state, &code, nullptr, 0, &cch);

   	// ��������� ���������� ������    
   	if (!SQL_SUCCEEDED(status) || cch == 0) return; std::wstring buffer(cch, 0);

   	// �������� ��������� �� ������
   	status = (*_pfnGetDiagRecW)(type, handle, 1, state, &code, &buffer[0], cch + 1, &cch);

	// ��� ���� ��������� �� �������
	for (SQLSMALLINT recNumber = 2; SQL_SUCCEEDED(status); recNumber++)
	{
		// ������� �������� ������
		ATRACE(TRACE_LEVEL_ERROR, "%ls-%d-%ls", state, code, buffer.c_str()); 

       	// ���������� ������ ������ ��� ���������
       	status = (*_pfnGetDiagRecW)(type, handle, recNumber, state, &code, nullptr, 0, &cch);

       	// ��������� ���������� ������    
       	if (!SQL_SUCCEEDED(status) || cch == 0) break; buffer.resize(cch); 

       	// �������� ��������� �� ������
       	status = (*_pfnGetDiagRecW)(type, handle, recNumber, state, &code, &buffer[0], cch + 1, &cch);
	}
}

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ��������������
///////////////////////////////////////////////////////////////////////////////
inline void format_odbc(trace::pprintf print, void* context, int level, va_list& args)
{
#if defined _MSC_VER && _MSC_VER >= 1600 

	// ������� ��� ������
	const odbc_error& error = va_arg(args, odbc_error); 
#else 
	// ������� ��������� ������
	const odbc_error_category* category = 
		(const odbc_error_category*)va_arg(args, const void*); 
	
	// ������� ��� ������
	odbc_error error(*category, va_arg(args, SQLRETURN));
#endif 
	// ���������� ��� ������
	std::string name = error.name(); 

	// ������� ��� ������
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(ODBC, format_odbc);

///////////////////////////////////////////////////////////////////////////////
// �������� ������������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
