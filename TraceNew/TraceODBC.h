#pragma once

///////////////////////////////////////////////////////////////////////////////
// Категория ошибок ODBC
///////////////////////////////////////////////////////////////////////////////
class odbc_error_category : public trace::error_category<SQLRETURN>
{
	// прототип функции SQLGetDiagRecW
	private: typedef SQLRETURN (SQL_API* PFNSQLGETDIAGRECW)(
    	SQLSMALLINT, SQLHANDLE, SQLSMALLINT, SQLWCHAR*, 
		SQLINTEGER*, SQLWCHAR*, SQLSMALLINT, SQLSMALLINT*
	);
	// адрес функции SQLGetDiagRecW
    private: PFNSQLGETDIAGRECW _pfnGetDiagRecW; 

	// конструктор
	public: odbc_error_category(HMODULE hModule) 
	{
        // получить адрес используемой функции
	    if (!hModule) _pfnGetDiagRecW = (PFNSQLGETDIAGRECW)::SQLGetDiagRecW;

        // получить адрес используемой функции
    	else _pfnGetDiagRecW = (PFNSQLGETDIAGRECW)::GetProcAddress(hModule, "SQLGetDiagRecW");
	}
    // получить сообщение об ошибке
    public: virtual std::string message(SQLRETURN status) const; 

    // получить дополнительную информацию об ошибке
    public: void trace(SQLHANDLE handle, SQLSMALLINT type) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки ODBC
///////////////////////////////////////////////////////////////////////////////
class odbc_error : public trace::error_code<SQLRETURN>
{
    // конструктор
    public: odbc_error(const odbc_error_category& category, SQLRETURN status) 
        
        // сохранить переданные параметры
        : trace::error_code<SQLRETURN>(status, category) {} 

	// признак наличия ошибки
	public: operator const void* () const 
	{ 
		// признак наличия ошибки
		return  (!SQL_SUCCEEDED(value())) ? this : (const void*)0; 
	}
    // символическое описание ошибки
    public: std::string name() const
    {	
    	// код ошибки
	   	switch (value())
        {
	    // получить описание статуса
	    case SQL_INVALID_HANDLE		 : return "SQL_INVALID_HANDLE"		; 
		case SQL_ERROR				 : return "SQL_ERROR"				; 
		case SQL_SUCCESS			 : return "SQL_SUCCESS"				;  
		case SQL_SUCCESS_WITH_INFO	 : return "SQL_SUCCESS_WITH_INFO"	; 
		case SQL_STILL_EXECUTING	 : return "SQL_STILL_EXECUTING"		; 
		case SQL_NEED_DATA			 : return "SQL_NEED_DATA"			; 
		case SQL_NO_DATA			 : return "SQL_NO_DATA"				; 
		case SQL_PARAM_DATA_AVAILABLE: return "SQL_PARAM_DATA_AVAILABLE"; 
    	}
        // отформатировать код ошибки
        char str[16]; trace::snprintf(str, sizeof(str), "%hd", value()); return str; 
	}
}; 
inline std::string odbc_error_category::message(SQLRETURN status) const
{
    // получить сообщение об ошибке
	return odbc_error(*this, status).name(); 
} 
///////////////////////////////////////////////////////////////////////////////
// Исключение ODBC
///////////////////////////////////////////////////////////////////////////////
class odbc_exception : public trace::exception<SQLRETURN>
{	
    // тип базового класса
    private: typedef trace::exception<SQLRETURN> base_type; 

	// описатель объекта и его тип
	private: SQLHANDLE _handle; SQLSMALLINT _type; 

    // конструктор
    public: odbc_exception(const odbc_error& error, 
		SQLHANDLE handle, SQLSMALLINT type, const char* szFile, int line)

        // сохранить переданные параметры
        : base_type(error, szFile, line), _handle(handle), _type(type) {}

	// получить дополнительную информацию об ошибке
    public: virtual void trace() const
	{
		// проверить наличие дополнительной информации
		if (value() != SQL_ERROR && value() != SQL_SUCCESS_WITH_INFO) return; 

		// получить дополнительную информацию об ошибке
		((const odbc_error_category&)code().category()).trace(_handle, _type); 
	} 
    // выбросить исключение
    public: virtual __noreturn void raise() const { trace(); throw *this; }
};

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (843BC251, CF10, 4C7B, B989, 9FD4A1244B08)
#include "TraceODBC.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Дополнительная информация об ошибке
///////////////////////////////////////////////////////////////////////////////
inline void odbc_error_category::trace(SQLHANDLE handle, SQLSMALLINT type) const
{
	// выделить буфер для отдельных полей описания
	SQLWCHAR state[6]; SQLINTEGER code; SQLSMALLINT cch;

   	// определить размер буфера для сообщения
   	SQLRETURN status = (*_pfnGetDiagRecW)(type, handle, 1, state, &code, nullptr, 0, &cch);

   	// проверить отсутствие ошибок    
   	if (!SQL_SUCCEEDED(status) || cch == 0) return; std::wstring buffer(cch, 0);

   	// получить сообщение об ошибке
   	status = (*_pfnGetDiagRecW)(type, handle, 1, state, &code, &buffer[0], cch + 1, &cch);

	// для всех сообщений об ошибках
	for (SQLSMALLINT recNumber = 2; SQL_SUCCEEDED(status); recNumber++)
	{
		// вывести описание ошибки
		ATRACE(TRACE_LEVEL_ERROR, "%ls-%d-%ls", state, code, buffer.c_str()); 

       	// определить размер буфера для сообщения
       	status = (*_pfnGetDiagRecW)(type, handle, recNumber, state, &code, nullptr, 0, &cch);

       	// проверить отсутствие ошибок    
       	if (!SQL_SUCCEEDED(status) || cch == 0) break; buffer.resize(cch); 

       	// получить сообщение об ошибке
       	status = (*_pfnGetDiagRecW)(type, handle, recNumber, state, &code, &buffer[0], cch + 1, &cch);
	}
}

///////////////////////////////////////////////////////////////////////////////
// Добавление способа форматирования
///////////////////////////////////////////////////////////////////////////////
inline void format_odbc(trace::pprintf print, void* context, int level, va_list& args)
{
#if defined _MSC_VER && _MSC_VER >= 1600 

	// извлечь код ошибки
	const odbc_error& error = va_arg(args, odbc_error); 
#else 
	// извлечь категорию ошибки
	const odbc_error_category* category = 
		(const odbc_error_category*)va_arg(args, const void*); 
	
	// создать код ошибки
	odbc_error error(*category, va_arg(args, SQLRETURN));
#endif 
	// определить имя ошибки
	std::string name = error.name(); 

	// вывести имя ошибки
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(ODBC, format_odbc);

///////////////////////////////////////////////////////////////////////////////
// Сбросить идентификатор служебных сообщений
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
