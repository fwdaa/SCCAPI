#pragma once

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ OCI
///////////////////////////////////////////////////////////////////////////////
class oci_error_category : public trace::error_category<sword>
{
	// ��������� ����� ���������
	private: OCIEnv* _envhp;

	// �����������
	public: oci_error_category(OCIEnv* envhp) : _envhp(envhp) {}

	// ��������� �������������� ���������
	public: std::wstring to_unicode(const char* str, 
		size_t cch = -1, bool stdexcept = false) const; 

	// ��������� �������������� ���������
	public: std::string from_unicode(const wchar_t* wstr, 
		size_t cch = -1, bool stdexcept = false) const; 

	// ������� ������������� ��������� UTF-16
	private: bool isCharsetUTF16() const
	{
		// ��������� ������� ���������
		if (!_envhp) return false; OCIError* errhp = nullptr;

		// ������� ��������� ������ 
		sword status = ::OCIHandleAlloc(_envhp, (void**)&errhp, OCI_HTYPE_ERROR, 0, nullptr); 

		// ��������� ���������� ������
		if (status < 0) return false; ub1 utf16 = 0;

		// �������� ������� ������������� UTF16-���������
		status = ::OCIAttrGet(_envhp, OCI_HTYPE_ENV, &utf16, nullptr, OCI_ATTR_ENV_UTF16, errhp);

		// ��������� ���������� ������
		if (status < 0) { utf16 = 0; } 
		
		// ���������� ��������� ������
		::OCIHandleFree(errhp, OCI_HTYPE_ERROR); return (utf16 != 0); 
	}
    // �������� ��������� �� ������
    public: virtual std::string message(sword status) const;

    // �������� �������������� ���������� �� ������
    public: void trace(OCIError* errhp) const
	{
		// �������� ������ ������
		if (!_envhp && !errhp) return;

	    // �������� �������������� ���������� �� ������
    	if (!errhp) trace(_envhp, OCI_HTYPE_ENV); 

	    // �������� �������������� ���������� �� ������
    	else trace(errhp, OCI_HTYPE_ERROR); 
	} 
    // �������� �������������� ���������� �� ������
    private: void trace(dvoid* hndlp, ub4 type) const; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������ OCI
///////////////////////////////////////////////////////////////////////////////
class oci_error : public trace::error_code<sword>
{
    // �����������
    public: oci_error(const oci_error_category& category, sword status) 
        
        // ��������� ���������� ���������
        : trace::error_code<sword>(status, category) {} 

	// ������� ������� ������
	public: operator const void* () const 
	{ 
		// ������� ������� ������
		return  (value() < 0) ? this : (const void*)0; 
	}
    // ������������� �������� ������
    public: std::string name() const
    {	
    	// ��� ������
	   	switch (value())
        {
	    // �������� �������� �������
	    case OCI_INVALID_HANDLE		 : return "OCI_INVALID_HANDLE"		; 
		case OCI_ERROR				 : return "OCI_ERROR"				; 
		case OCI_SUCCESS			 : return "OCI_SUCCESS"				;  
		case OCI_SUCCESS_WITH_INFO	 : return "OCI_SUCCESS_WITH_INFO"	; 
		case OCI_STILL_EXECUTING	 : return "OCI_STILL_EXECUTING"		; 
		case OCI_NEED_DATA			 : return "OCI_NEED_DATA"			; 
		case OCI_NO_DATA			 : return "OCI_NO_DATA"				; 
    	}
        // ��������������� ��� ������
        char str[16]; trace::snprintf(str, sizeof(str), "%d", value()); return str; 
	}
}; 
inline std::string oci_error_category::message(sword status) const
{
	// ������� ��������� �� ������
	return oci_error(*this, status).name(); 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� OCI
///////////////////////////////////////////////////////////////////////////////
class oci_exception : public trace::exception<sword>
{	
	// ��� �������� ������
	private: typedef trace::exception<sword> base_type;

	// ������ ������
	private: OCIError* _errhp;  

    // �����������
    public: oci_exception(const oci_error_category& category, 
		sword status, OCIError* errhp, const char* szFile, int line)

        // ��������� ���������� ���������
        : base_type(oci_error(category, status), szFile, line), _errhp(errhp) {}

    // �����������
    public: oci_exception(const oci_error& error, 
		OCIError* errhp, const char* szFile, int line)

        // ��������� ���������� ���������
        : base_type(error, szFile, line), _errhp(errhp) {}

    // ��������� ����������
    public: virtual void trace() const
	{
		// ��������� ������� �������������� ����������
		if (value() != OCI_ERROR && value() != OCI_SUCCESS_WITH_INFO) return; 

	    // �������� �������������� ���������� �� ������
		((const oci_error_category&)code().category()).trace(_errhp); 
	} 
    // ��������� ����������
    public: virtual __noreturn void raise() const { trace(); throw *this; }
};

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (26FA3CA2, 2C11, 4A76, ABB8, 16BD595AB976)
#include "TraceOCI.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������������� ������� ��������
///////////////////////////////////////////////////////////////////////////////
inline std::wstring oci_error_category::to_unicode(
	const char* str, size_t cch, bool stdexcept) const
{
	// ��������� ������� ������ � ���������
	if (cch == 0) return std::wstring(); if (!_envhp) return ::to_unicode(str, cch);

	// ���������� ������ ������
	size_t size; if (cch == (size_t)(-1)) cch = strlen(str); 

	// ���������� ��������� ������ ������
	sword status = ::OCICharSetToUnicode(_envhp, nullptr, 0, (const text*)str, cch, &size); 

	// ��������� �������������� ��������� UTF-16BE
	if (status < 0 && isCharsetUTF16()) return from_utf16be(str, cch);

	// ��������� ���������� ������
	if (status < 0 && stdexcept) throw std::range_error("bad conversion");

	// ��������� ���������� ������ � �������� ����� ���������� �������
	AE_CHECK_OCI(*this, status, nullptr); std::wstring wstr(size, 0);

	// ��������� �������������� ��������
	status = ::OCICharSetToUnicode(_envhp, (ub2*)&wstr[0], size, (const text*)str, cch, &size);
 
	// ��������� �������������� ��������� UTF-16BE
	if (status < 0 && isCharsetUTF16()) return from_utf16be(str, cch);

	// ��������� ���������� ������
	if (status < 0 && stdexcept) throw std::range_error("bad conversion");

	// ��������� ���������� ������ � ��������������� ������ ������
	AE_CHECK_OCI(*this, status, nullptr); wstr.resize(size); return wstr;
}

inline std::string oci_error_category::from_unicode(
	const wchar_t* wstr, size_t cch, bool stdexcept) const
{
	// ��������� ������� ������ � ���������
	if (cch == 0) return std::string(); if (!_envhp) return ::from_unicode(wstr, cch);

	// ���������� ������ ������
	size_t size; if (cch == (size_t)(-1)) cch = wcslen(wstr); 

	// �������� ����� ���������� �������
	std::basic_string<ub2> ustr(cch, 0); for (size_t i = 0; i < cch; i++)
	{
		// ����������� �������� �������
		ustr[i] = (wstr[i] <= 0xFFFF) ? (ub2)wstr[i] : (ub2)0xFFFD; 
	}
	// ���������� ��������� ������ ������
	sword status = ::OCIUnicodeToCharSet(_envhp, nullptr, 0, ustr.c_str(), cch, &size); 

	// ��������� �������������� ��������� UTF-16BE
	if (status < 0 && isCharsetUTF16()) return to_utf16be(wstr, cch);

	// ��������� ���������� ������
	if (status < 0 && stdexcept) throw std::range_error("bad conversion");

	// ��������� ���������� ������ � �������� ����� ���������� �������
	AE_CHECK_OCI(*this, status, nullptr); std::string str(size, 0);

	// ��������� �������������� ��������
	status = ::OCIUnicodeToCharSet(_envhp, (OraText*)&str[0], size, ustr.c_str(), cch, &size);
 
	// ��������� �������������� ��������� UTF-16BE
	if (status < 0 && isCharsetUTF16()) return to_utf16be(wstr, cch);

	// ��������� ���������� ������
	if (status < 0 && stdexcept) throw std::range_error("bad conversion");

	// ��������� ���������� ������ � ��������������� ������ ������
	AE_CHECK_OCI(*this, status, nullptr); str.resize(size); return str;
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� �� ������
///////////////////////////////////////////////////////////////////////////////
inline void oci_error_category::trace(dvoid* hndlp, ub4 type) const
{
	// �������� ����� ���������� �������
	char errbuf[512]; sb4 errcode; sword status; 

	// �������� ��������� � ������ ������
	status = ::OCIErrorGet(hndlp, 1, 
		nullptr, &errcode, (text*)errbuf, sizeof(errbuf), type
	);
	// ��� ���� ��������� �� �������
	for (ub4 recordno = 2; status == OCI_SUCCESS; recordno++)
	{
		try { 
			// �������� ��������� �������� ������
			std::wstring buffer = to_unicode(errbuf, strlen(errbuf), true); 

			// ������� �������� ������
			ATRACE(TRACE_LEVEL_ERROR, "OCI-%d-%ls", errcode, buffer.c_str()); 
		}
		// ��� ������������� ������
		catch (const std::exception&) 
		{ 
			// ������� �������� ������
			ATRACE(TRACE_LEVEL_ERROR, "OCI-%d-%hs", errcode, errbuf); 
		}
		// �������� ��������� �� ������
		status = ::OCIErrorGet(hndlp, recordno, 
			nullptr, &errcode, (text*)errbuf, sizeof(errbuf), type
		);
	}
}  

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ��������������
///////////////////////////////////////////////////////////////////////////////
inline void format_oci(trace::pprintf print, void* context, int level, va_list& args)
{
#if defined _MSC_VER && _MSC_VER >= 1600 

	// ������� ��� ������
	const oci_error& error = va_arg(args, oci_error); 
#else 
	// ������� ��������� ������
	const oci_error_category* category = 
		(const oci_error_category*)va_arg(args, const void*); 
	
	// ������� ��� ������
	oci_error error(*category, va_arg(args, sword));
#endif 
	// ���������� ��� ������
	std::string name = error.name(); 

	// ������� ��� ������
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(OCI, format_oci);

///////////////////////////////////////////////////////////////////////////////
// �������� ������������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
