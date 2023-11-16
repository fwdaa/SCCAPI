#pragma once
#include "TraceError.h"
#include "openssl/err.h"

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
// Исключение OpenSSL
///////////////////////////////////////////////////////////////////////////////
class openssl_error : public trace::system_error<unsigned long>
{
    // конструктор
    public: openssl_error(unsigned long code)

        // сохранить переданные параметры
        : trace::system_error<unsigned long>(code, openssl_category()) {}

    // выбросить исключение
    public: virtual _NORETURN void raise(const char* szFile, int line) const 
    { 
        // выбросить исключение
        trace(szFile, line); throw *this; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок OpenSSL
///////////////////////////////////////////////////////////////////////////////
#define WPP_TRACELEVEL_OPENSSL_RAISE(FILE, LINE)                            \
    openssl_error(WPP_VAR(LINE)).raise(FILE, LINE);    

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_OPENSSL(LEVEL, RET)       	(unsigned long, (RET) ? 0 : ERR_get_error(), WPP_CAST_BOOL, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_OPENSSL_PRE(LEVEL, RET)      

// Проверка наличия трассировки
#define WPP_TRACELEVEL_OPENSSL_ENABLED(LEVEL, RET)   	WPP_VAR(__LINE__)

// Проверка наличия ошибки
#define WPP_TRACELEVEL_OPENSSL_POST(LEVEL, RET)                             \
    ; if (WPP_TRACELEVEL_OPENSSL_ENABLED(LEVEL, RET)) {                     \
         WPP_TRACELEVEL_OPENSSL_RAISE(__FILE__, __LINE__)                   \
    }}

///////////////////////////////////////////////////////////////////////////////
// Определение трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_OPENSSL_LOGGER(LEVEL, RET)   	WppGetLogger(),
#else 
#define AE_CHECK_OPENSSL(RET)                                                                     		        \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_OPENSSL(TRACE_LEVEL_ERROR, RET), "ERROR %!ULONG!", WPP_VAR(__LINE__))      \
    WPP_TRACELEVEL_OPENSSL_PRE(TRACE_LEVEL_ERROR, RET)                                            		        \
    (void)((                                                                                                    \
        WPP_TRACELEVEL_OPENSSL_ENABLED(TRACE_LEVEL_ERROR, RET)                                    		        \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!ULONG!", WPP_VAR(__LINE__))), 1 : 0                                    \
    ))                                                                                            		        \
    WPP_TRACELEVEL_OPENSSL_POST(TRACE_LEVEL_ERROR, RET)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Отмена действия макросов
///////////////////////////////////////////////////////////////////////////////
#undef _NORETURN
