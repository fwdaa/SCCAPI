#pragma once

///////////////////////////////////////////////////////////////////////////////
// Категория ошибок OCI
///////////////////////////////////////////////////////////////////////////////
class oci_error_category : public trace::error_category<sword>
{
	// описатель среды окружения
	private: OCIEnv* _envhp;

	// конструктор
	public: oci_error_category(OCIEnv* envhp) : _envhp(envhp) {}

	// выполнить преобразование кодировки
	public: std::wstring to_unicode(const char* str, 
		size_t cch = -1, bool stdexcept = false) const; 

	// выполнить преобразование кодировки
	public: std::string from_unicode(const wchar_t* wstr, 
		size_t cch = -1, bool stdexcept = false) const; 

	// признак использования кодировки UTF-16
	private: bool isCharsetUTF16() const
	{
		// проверить наличие описателя
		if (!_envhp) return false; OCIError* errhp = nullptr;

		// создать описатель ошибок 
		sword status = ::OCIHandleAlloc(_envhp, (void**)&errhp, OCI_HTYPE_ERROR, 0, nullptr); 

		// проверить отсутствие ошибок
		if (status < 0) return false; ub1 utf16 = 0;

		// получить признак использования UTF16-кодировки
		status = ::OCIAttrGet(_envhp, OCI_HTYPE_ENV, &utf16, nullptr, OCI_ATTR_ENV_UTF16, errhp);

		// проверить отсутствие ошибок
		if (status < 0) { utf16 = 0; } 
		
		// освободить описатель ошибок
		::OCIHandleFree(errhp, OCI_HTYPE_ERROR); return (utf16 != 0); 
	}
    // получить сообщение об ошибке
    public: virtual std::string message(sword status) const;

    // получить дополнительную информацию об ошибке
    public: void trace(OCIError* errhp) const
	{
		// получить объект ошибки
		if (!_envhp && !errhp) return;

	    // получить дополнительную информацию об ошибке
    	if (!errhp) trace(_envhp, OCI_HTYPE_ENV); 

	    // получить дополнительную информацию об ошибке
    	else trace(errhp, OCI_HTYPE_ERROR); 
	} 
    // получить дополнительную информацию об ошибке
    private: void trace(dvoid* hndlp, ub4 type) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки OCI
///////////////////////////////////////////////////////////////////////////////
class oci_error : public trace::error_code<sword>
{
    // конструктор
    public: oci_error(const oci_error_category& category, sword status) 
        
        // сохранить переданные параметры
        : trace::error_code<sword>(status, category) {} 

	// признак наличия ошибки
	public: operator const void* () const 
	{ 
		// признак наличия ошибки
		return  (value() < 0) ? this : (const void*)0; 
	}
    // символическое описание ошибки
    public: std::string name() const
    {	
    	// код ошибки
	   	switch (value())
        {
	    // получить описание статуса
	    case OCI_INVALID_HANDLE		 : return "OCI_INVALID_HANDLE"		; 
		case OCI_ERROR				 : return "OCI_ERROR"				; 
		case OCI_SUCCESS			 : return "OCI_SUCCESS"				;  
		case OCI_SUCCESS_WITH_INFO	 : return "OCI_SUCCESS_WITH_INFO"	; 
		case OCI_STILL_EXECUTING	 : return "OCI_STILL_EXECUTING"		; 
		case OCI_NEED_DATA			 : return "OCI_NEED_DATA"			; 
		case OCI_NO_DATA			 : return "OCI_NO_DATA"				; 
    	}
        // отформатировать код ошибки
        char str[16]; trace::snprintf(str, sizeof(str), "%d", value()); return str; 
	}
}; 
inline std::string oci_error_category::message(sword status) const
{
	// вернуть сообщение об ошибке
	return oci_error(*this, status).name(); 
}

///////////////////////////////////////////////////////////////////////////////
// Исключение OCI
///////////////////////////////////////////////////////////////////////////////
class oci_exception : public trace::exception<sword>
{	
	// тип базового класса
	private: typedef trace::exception<sword> base_type;

	// объект ошибки
	private: OCIError* _errhp;  

    // конструктор
    public: oci_exception(const oci_error_category& category, 
		sword status, OCIError* errhp, const char* szFile, int line)

        // сохранить переданные параметры
        : base_type(oci_error(category, status), szFile, line), _errhp(errhp) {}

    // конструктор
    public: oci_exception(const oci_error& error, 
		OCIError* errhp, const char* szFile, int line)

        // сохранить переданные параметры
        : base_type(error, szFile, line), _errhp(errhp) {}

    // выбросить исключение
    public: virtual void trace() const
	{
		// проверить наличие дополнительной информации
		if (value() != OCI_ERROR && value() != OCI_SUCCESS_WITH_INFO) return; 

	    // получить дополнительную информацию об ошибке
		((const oci_error_category&)code().category()).trace(_errhp); 
	} 
    // выбросить исключение
    public: virtual __noreturn void raise() const { trace(); throw *this; }
};

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (26FA3CA2, 2C11, 4A76, ABB8, 16BD595AB976)
#include "TraceOCI.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Преобразования наборов символов
///////////////////////////////////////////////////////////////////////////////
inline std::wstring oci_error_category::to_unicode(
	const char* str, size_t cch, bool stdexcept) const
{
	// проверить наличие строки и описателя
	if (cch == 0) return std::wstring(); if (!_envhp) return ::to_unicode(str, cch);

	// определить размер строки
	size_t size; if (cch == (size_t)(-1)) cch = strlen(str); 

	// определить требуемый размер буфера
	sword status = ::OCICharSetToUnicode(_envhp, nullptr, 0, (const text*)str, cch, &size); 

	// выполнить преобразование кодировки UTF-16BE
	if (status < 0 && isCharsetUTF16()) return from_utf16be(str, cch);

	// проверить отсутствие ошибок
	if (status < 0 && stdexcept) throw std::range_error("bad conversion");

	// проверить отсутствие ошибок и выделить буфер требуемого размера
	AE_CHECK_OCI(*this, status, nullptr); std::wstring wstr(size, 0);

	// выполнить преобразование символов
	status = ::OCICharSetToUnicode(_envhp, (ub2*)&wstr[0], size, (const text*)str, cch, &size);
 
	// выполнить преобразование кодировки UTF-16BE
	if (status < 0 && isCharsetUTF16()) return from_utf16be(str, cch);

	// проверить отсутствие ошибок
	if (status < 0 && stdexcept) throw std::range_error("bad conversion");

	// проверить отсутствие ошибок и скорректировать размер строки
	AE_CHECK_OCI(*this, status, nullptr); wstr.resize(size); return wstr;
}

inline std::string oci_error_category::from_unicode(
	const wchar_t* wstr, size_t cch, bool stdexcept) const
{
	// проверить наличие строки и описателя
	if (cch == 0) return std::string(); if (!_envhp) return ::from_unicode(wstr, cch);

	// определить размер строки
	size_t size; if (cch == (size_t)(-1)) cch = wcslen(wstr); 

	// выделить буфер требуемого размера
	std::basic_string<ub2> ustr(cch, 0); for (size_t i = 0; i < cch; i++)
	{
		// скопировать значение символа
		ustr[i] = (wstr[i] <= 0xFFFF) ? (ub2)wstr[i] : (ub2)0xFFFD; 
	}
	// определить требуемый размер буфера
	sword status = ::OCIUnicodeToCharSet(_envhp, nullptr, 0, ustr.c_str(), cch, &size); 

	// выполнить преобразование кодировки UTF-16BE
	if (status < 0 && isCharsetUTF16()) return to_utf16be(wstr, cch);

	// проверить отсутствие ошибок
	if (status < 0 && stdexcept) throw std::range_error("bad conversion");

	// проверить отсутствие ошибок и выделить буфер требуемого размера
	AE_CHECK_OCI(*this, status, nullptr); std::string str(size, 0);

	// выполнить преобразование символов
	status = ::OCIUnicodeToCharSet(_envhp, (OraText*)&str[0], size, ustr.c_str(), cch, &size);
 
	// выполнить преобразование кодировки UTF-16BE
	if (status < 0 && isCharsetUTF16()) return to_utf16be(wstr, cch);

	// проверить отсутствие ошибок
	if (status < 0 && stdexcept) throw std::range_error("bad conversion");

	// проверить отсутствие ошибок и скорректировать размер строки
	AE_CHECK_OCI(*this, status, nullptr); str.resize(size); return str;
}

///////////////////////////////////////////////////////////////////////////////
// Дополнительная информация об ошибке
///////////////////////////////////////////////////////////////////////////////
inline void oci_error_category::trace(dvoid* hndlp, ub4 type) const
{
	// выделить буфер требуемого размера
	char errbuf[512]; sb4 errcode; sword status; 

	// получить сообщение о первой ошибке
	status = ::OCIErrorGet(hndlp, 1, 
		nullptr, &errcode, (text*)errbuf, sizeof(errbuf), type
	);
	// для всех сообщений об ошибках
	for (ub4 recordno = 2; status == OCI_SUCCESS; recordno++)
	{
		try { 
			// получить строковое описание ошибки
			std::wstring buffer = to_unicode(errbuf, strlen(errbuf), true); 

			// вывести описание ошибки
			ATRACE(TRACE_LEVEL_ERROR, "OCI-%d-%ls", errcode, buffer.c_str()); 
		}
		// при возникновении ошибки
		catch (const std::exception&) 
		{ 
			// вывести описание ошибки
			ATRACE(TRACE_LEVEL_ERROR, "OCI-%d-%hs", errcode, errbuf); 
		}
		// получить сообщение об ошибке
		status = ::OCIErrorGet(hndlp, recordno, 
			nullptr, &errcode, (text*)errbuf, sizeof(errbuf), type
		);
	}
}  

///////////////////////////////////////////////////////////////////////////////
// Добавление способа форматирования
///////////////////////////////////////////////////////////////////////////////
inline void format_oci(trace::pprintf print, void* context, int level, va_list& args)
{
#if defined _MSC_VER && _MSC_VER >= 1600 

	// извлечь код ошибки
	const oci_error& error = va_arg(args, oci_error); 
#else 
	// извлечь категорию ошибки
	const oci_error_category* category = 
		(const oci_error_category*)va_arg(args, const void*); 
	
	// создать код ошибки
	oci_error error(*category, va_arg(args, sword));
#endif 
	// определить имя ошибки
	std::string name = error.name(); 

	// вывести имя ошибки
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(OCI, format_oci);

///////////////////////////////////////////////////////////////////////////////
// Сбросить идентификатор служебных сообщений
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
