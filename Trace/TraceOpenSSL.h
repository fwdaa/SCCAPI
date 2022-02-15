#pragma once
#include "openssl/err.h"

///////////////////////////////////////////////////////////////////////////////
// Категория ошибок OpenSSL
///////////////////////////////////////////////////////////////////////////////
class _openssl_category : public trace::error_category<unsigned long>
{
    // получить сообщение об ошибке
    public: virtual std::string message(unsigned long code) const 
    {
        // получить сообщение об ошибке
        char msg[120]; ERR_error_string_n(code, msg, sizeof(msg)); return msg; 
    }
};
inline const _openssl_category& openssl_category() 
{
    // категория ошибок POSIX
    static _openssl_category openssl_category; return openssl_category; 
}

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки OpenSSL
///////////////////////////////////////////////////////////////////////////////
class openssl_error : public trace::error_code<unsigned long>
{
    // конструктор
    public: openssl_error(unsigned long code) 
        
        // сохранить код ошибки
        : trace::error_code<unsigned long>(code, openssl_category()) {}

    // символическое описание ошибки
    public: std::string name() const
    {	
        // отформатировать код ошибки
        char str[16]; trace::snprintf(str, sizeof(str), "%lu", value()); return str; 
	}

};
// признак наличия ошибки
inline bool is_openssl_error(unsigned long code) { return code != 0; }

///////////////////////////////////////////////////////////////////////////////
// Исключение OpenSSL
///////////////////////////////////////////////////////////////////////////////
class openssl_exception : public trace::exception<unsigned long>
{
    // конструктор
    public: openssl_exception(unsigned long code, const char* szFile, int line)

        // сохранить переданные параметры
        : trace::exception<unsigned long>(openssl_error(code), szFile, line) {}

    // выбросить исключение
    public: void raise() const { trace(); throw *this; }
};

///////////////////////////////////////////////////////////////////////////////
// Добавление способа форматирования
///////////////////////////////////////////////////////////////////////////////
inline void format_openssl(trace::pprintf print, void* context, int level, va_list& args)
{
	// извлечь код ошибки
	openssl_error error(va_arg(args, unsigned long)); 

	// получить символическое имя
	std::string name = error.name(); 

	// вывести символическое имя
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(OPENSSL, format_openssl); 
