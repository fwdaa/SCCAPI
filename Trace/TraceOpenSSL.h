#pragma once
#include "openssl/err.h"

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ OpenSSL
///////////////////////////////////////////////////////////////////////////////
class _openssl_category : public trace::error_category<unsigned long>
{
    // �������� ��������� �� ������
    public: virtual std::string message(unsigned long code) const 
    {
        // �������� ��������� �� ������
        char msg[120]; ERR_error_string_n(code, msg, sizeof(msg)); return msg; 
    }
};
inline const _openssl_category& openssl_category() 
{
    // ��������� ������ POSIX
    static _openssl_category openssl_category; return openssl_category; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������ OpenSSL
///////////////////////////////////////////////////////////////////////////////
class openssl_error : public trace::error_code<unsigned long>
{
    // �����������
    public: openssl_error(unsigned long code) 
        
        // ��������� ��� ������
        : trace::error_code<unsigned long>(code, openssl_category()) {}

    // ������������� �������� ������
    public: std::string name() const
    {	
        // ��������������� ��� ������
        char str[16]; trace::snprintf(str, sizeof(str), "%lu", value()); return str; 
	}

};
// ������� ������� ������
inline bool is_openssl_error(unsigned long code) { return code != 0; }

///////////////////////////////////////////////////////////////////////////////
// ���������� OpenSSL
///////////////////////////////////////////////////////////////////////////////
class openssl_exception : public trace::exception<unsigned long>
{
    // �����������
    public: openssl_exception(unsigned long code, const char* szFile, int line)

        // ��������� ���������� ���������
        : trace::exception<unsigned long>(openssl_error(code), szFile, line) {}

    // ��������� ����������
    public: void raise() const { trace(); throw *this; }
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ��������������
///////////////////////////////////////////////////////////////////////////////
inline void format_openssl(trace::pprintf print, void* context, int level, va_list& args)
{
	// ������� ��� ������
	openssl_error error(va_arg(args, unsigned long)); 

	// �������� ������������� ���
	std::string name = error.name(); 

	// ������� ������������� ���
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(OPENSSL, format_openssl); 
