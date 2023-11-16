#pragma once
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
// Категория ошибок PKCS11
///////////////////////////////////////////////////////////////////////////////
class pkcs11_error_category : public trace::error_category<CK_ULONG>
{
    // получить сообщение об ошибке
    public: virtual std::string message(CK_ULONG code) const; 
};

inline const class pkcs11_error_category& pkcs11_category() 
{
    // категория ошибок PKCS11
    static class pkcs11_error_category pkcs11_category; return pkcs11_category; 
}

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки PKCS11
///////////////////////////////////////////////////////////////////////////////
class pkcs11_error_code : public trace::error_code<CK_ULONG>
{
    // код ошибки
    private: char _code[16]; 

    // конструктор
    public: pkcs11_error_code(CK_ULONG code) 
        
        // сохранить переданные параметры
        : trace::error_code<CK_ULONG>(code, pkcs11_category()) 
	{
        // отформатировать код ошибки
        trace::snprintf(_code, sizeof(_code), "%08lX", code); 
	} 
   	// символическое описание ошибки
   	public: const char* name() const
   	{
   		// код ошибки
   		switch (value())
       	{
    	case CKR_OK								    : return "CKR_OK"; 
    	case CKR_CANCEL							    : return "CKR_CANCEL";				
		case CKR_HOST_MEMORY						: return "CKR_HOST_MEMORY";
		case CKR_SLOT_ID_INVALID					: return "CKR_SLOT_ID_INVALID";
		case CKR_GENERAL_ERROR					    : return "CKR_GENERAL_ERROR";
		case CKR_FUNCTION_FAILED					: return "CKR_FUNCTION_FAILED";
		case CKR_ARGUMENTS_BAD					    : return "CKR_ARGUMENTS_BAD";
		case CKR_NO_EVENT							: return "CKR_NO_EVENT";
		case CKR_NEED_TO_CREATE_THREADS			    : return "CKR_NEED_TO_CREATE_THREADS";
		case CKR_CANT_LOCK						    : return "CKR_CANT_LOCK";
		case CKR_ATTRIBUTE_READ_ONLY				: return "CKR_ATTRIBUTE_READ_ONLY";	
		case CKR_ATTRIBUTE_SENSITIVE				: return "CKR_ATTRIBUTE_SENSITIVE";
		case CKR_ATTRIBUTE_TYPE_INVALID			    : return "CKR_ATTRIBUTE_TYPE_INVALID";
		case CKR_ATTRIBUTE_VALUE_INVALID			: return "CKR_ATTRIBUTE_VALUE_INVALID";
		case CKR_DATA_INVALID						: return "CKR_DATA_INVALID";
		case CKR_DATA_LEN_RANGE					    : return "CKR_DATA_LEN_RANGE";
		case CKR_DEVICE_ERROR						: return "CKR_DEVICE_ERROR";
		case CKR_DEVICE_MEMORY					    : return "CKR_DEVICE_MEMORY";
		case CKR_DEVICE_REMOVED					    : return "CKR_DEVICE_REMOVED";
		case CKR_ENCRYPTED_DATA_INVALID			    : return "CKR_ENCRYPTED_DATA_INVALID";
		case CKR_ENCRYPTED_DATA_LEN_RANGE			: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
		case CKR_FUNCTION_CANCELED				    : return "CKR_FUNCTION_CANCELED";
		case CKR_FUNCTION_NOT_PARALLEL			    : return "CKR_FUNCTION_NOT_PARALLEL";
		case CKR_FUNCTION_NOT_SUPPORTED			    : return "CKR_FUNCTION_NOT_SUPPORTED"; 
		case CKR_KEY_HANDLE_INVALID				    : return "CKR_KEY_HANDLE_INVALID";
		case CKR_KEY_SIZE_RANGE					    : return "CKR_KEY_SIZE_RANGE";
		case CKR_KEY_TYPE_INCONSISTENT			    : return "CKR_KEY_TYPE_INCONSISTENT";
		case CKR_KEY_NOT_NEEDED					    : return "CKR_KEY_NOT_NEEDED";
		case CKR_KEY_CHANGED						: return "CKR_KEY_CHANGED";
		case CKR_KEY_NEEDED						    : return "CKR_KEY_NEEDED";
		case CKR_KEY_INDIGESTIBLE					: return "CKR_KEY_INDIGESTIBLE";
		case CKR_KEY_FUNCTION_NOT_PERMITTED		    : return "CKR_KEY_FUNCTION_NOT_PERMITTED";
		case CKR_KEY_NOT_WRAPPABLE				    : return "CKR_KEY_NOT_WRAPPABLE";
		case CKR_KEY_UNEXTRACTABLE				    : return "CKR_KEY_UNEXTRACTABLE";
		case CKR_MECHANISM_INVALID				    : return "CKR_MECHANISM_INVALID";
		case CKR_MECHANISM_PARAM_INVALID			: return "CKR_MECHANISM_PARAM_INVALID";
		case CKR_OBJECT_HANDLE_INVALID			    : return "CKR_OBJECT_HANDLE_INVALID";
		case CKR_OPERATION_ACTIVE					: return "CKR_OPERATION_ACTIVE";
		case CKR_OPERATION_NOT_INITIALIZED		    : return "CKR_OPERATION_NOT_INITIALIZED";
		case CKR_PIN_INCORRECT					    : return "CKR_PIN_INCORRECT";
		case CKR_PIN_INVALID						: return "CKR_PIN_INVALID";
		case CKR_PIN_LEN_RANGE					    : return "CKR_PIN_LEN_RANGE";
		case CKR_PIN_EXPIRED						: return "CKR_PIN_EXPIRED";
		case CKR_PIN_LOCKED						    : return "CKR_PIN_LOCKED";
		case CKR_SESSION_CLOSED					    : return "CKR_SESSION_CLOSED";
		case CKR_SESSION_COUNT					    : return "CKR_SESSION_COUNT";
		case CKR_SESSION_HANDLE_INVALID			    : return "CKR_SESSION_HANDLE_INVALID";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED	    : return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		case CKR_SESSION_READ_ONLY				    : return "CKR_SESSION_READ_ONLY";
		case CKR_SESSION_EXISTS					    : return "CKR_SESSION_EXISTS";
		case CKR_SESSION_READ_ONLY_EXISTS			: return "CKR_SESSION_READ_ONLY_EXISTS";
		case CKR_SESSION_READ_WRITE_SO_EXISTS		: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
		case CKR_SIGNATURE_INVALID				    : return "CKR_SIGNATURE_INVALID";
		case CKR_SIGNATURE_LEN_RANGE				: return "CKR_SIGNATURE_LEN_RANGE";
		case CKR_TEMPLATE_INCOMPLETE				: return "CKR_TEMPLATE_INCOMPLETE";
		case CKR_TEMPLATE_INCONSISTENT			    : return "CKR_TEMPLATE_INCONSISTENT";
		case CKR_TOKEN_NOT_PRESENT				    : return "CKR_TOKEN_NOT_PRESENT";
		case CKR_TOKEN_NOT_RECOGNIZED				: return "CKR_TOKEN_NOT_RECOGNIZED";
		case CKR_TOKEN_WRITE_PROTECTED			    : return "CKR_TOKEN_WRITE_PROTECTED";
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID	    : return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		case CKR_UNWRAPPING_KEY_SIZE_RANGE		    : return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT	: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_USER_ALREADY_LOGGED_IN			    : return "CKR_USER_ALREADY_LOGGED_IN";
		case CKR_USER_NOT_LOGGED_IN				    : return "CKR_USER_NOT_LOGGED_IN";
		case CKR_USER_PIN_NOT_INITIALIZED			: return "CKR_USER_PIN_NOT_INITIALIZED";
		case CKR_USER_TYPE_INVALID				    : return "CKR_USER_TYPE_INVALID";
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN	    : return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		case CKR_USER_TOO_MANY_TYPES				: return "CKR_USER_TOO_MANY_TYPES";
		case CKR_WRAPPED_KEY_INVALID				: return "CKR_WRAPPED_KEY_INVALID";
		case CKR_WRAPPED_KEY_LEN_RANGE			    : return "CKR_WRAPPED_KEY_LEN_RANGE";
		case CKR_WRAPPING_KEY_HANDLE_INVALID		: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
		case CKR_WRAPPING_KEY_SIZE_RANGE			: return "CKR_WRAPPING_KEY_SIZE_RANGE";
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT	    : return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_RANDOM_SEED_NOT_SUPPORTED		    : return "CKR_RANDOM_SEED_NOT_SUPPORTED";
		case CKR_RANDOM_NO_RNG					    : return "CKR_RANDOM_NO_RNG";
		case CKR_BUFFER_TOO_SMALL					: return "CKR_BUFFER_TOO_SMALL";
		case CKR_SAVED_STATE_INVALID				: return "CKR_SAVED_STATE_INVALID";
		case CKR_INFORMATION_SENSITIVE			    : return "CKR_INFORMATION_SENSITIVE";
		case CKR_STATE_UNSAVEABLE					: return "CKR_STATE_UNSAVEABLE";
		case CKR_CRYPTOKI_NOT_INITIALIZED			: return "CKR_CRYPTOKI_NOT_INITIALIZED";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED		: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		case CKR_MUTEX_BAD						    : return "CKR_MUTEX_BAD";
		case CKR_MUTEX_NOT_LOCKED					: return "CKR_MUTEX_NOT_LOCKED";
		case CKR_VENDOR_DEFINED					    : return "CKR_VENDOR_DEFINED";
		}
		return _code; 
	}
}; 
inline std::string pkcs11_error_category::message(CK_ULONG code) const
{
	// вернуть сообщение об ошибке
	return pkcs11_error(code).name(); 
} 
///////////////////////////////////////////////////////////////////////////////
// Исключение PKCS11
///////////////////////////////////////////////////////////////////////////////
class pkcs11_error : public trace::system_error<CK_ULONG>
{
    // конструктор
    public: pkcs11_error(const pkcs11_error_code& code)

        // сохранить переданные параметры
        : trace::system_error<CK_ULONG>(code) {}

    // конструктор
    public: pkcs11_error(CK_ULONG code)

        // сохранить переданные параметры
        : trace::system_error<CK_ULONG>(code, pkcs11_category()) {}

    // выбросить исключение
    public: virtual _NORETURN void raise(const char* szFile, int line) const 
	{ 
		// выбросить исключение
		trace(szFile, line); throw *this; 
	}
	// имя ошибки 
	public: std::string name() const 
	{
		// вернуть имя ошибки 
		return code().category().message(code().value()); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Добавление способа форматирования
///////////////////////////////////////////////////////////////////////////////
inline void format_pkcs11(trace::pprintf print, void* context, int level, va_list& args)
{
	// извлечь код ошибки
	pkcs11_error_code error(va_arg(args, CK_ULONG)); 

	// определить имя ошибки
	std::string name = error.name(); 

	// вывести имя ошибки
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(PKCS11, format_pkcs11);

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок PKCS11
///////////////////////////////////////////////////////////////////////////////
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_PKCS11_RAISE(FILE, LINE)    	                        \
    pkcs11_error(WPP_VAR(LINE), FILE, LINE).trace();						\
    throw gcnew Aladdin::PKCS11::Exception(WPP_VAR(LINE));
#else 
#define WPP_TRACELEVEL_PKCS11_RAISE(FILE, LINE)           	                \
    pkcs11_error(WPP_VAR(LINE)).raise(FILE, LINE);    
#endif 

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_PKCS11(LEVEL, CODE)       	(CK_ULONG, CODE, WPP_CAST_BOOL, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_PKCS11_PRE(LEVEL, CODE)      

// Проверка наличия трассировки
#define WPP_TRACELEVEL_PKCS11_ENABLED(LEVEL, CODE)   	WPP_VAR(__LINE__)

// Проверка наличия ошибки
#define WPP_TRACELEVEL_PKCS11_POST(LEVEL, CODE)                             \
    ; if (WPP_TRACELEVEL_PKCS11_ENABLED(LEVEL, CODE)) {                     \
         WPP_TRACELEVEL_PKCS11_RAISE(__FILE__, __LINE__)                    \
    }}

///////////////////////////////////////////////////////////////////////////////
// Определение трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_PKCS11_LOGGER(LEVEL, CODE)   	WppGetLogger(),
#else 
#define AE_CHECK_PKCS11(CODE)                                                               			    	\
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_PKCS11(TRACE_LEVEL_ERROR, CODE), "ERROR %!PKCS11!", WPP_VAR(__LINE__))   	\
    WPP_TRACELEVEL_PKCS11_PRE(TRACE_LEVEL_ERROR, CODE)                               	            			\
    (void)((                                                                                      			    \
        WPP_TRACELEVEL_PKCS11_ENABLED(TRACE_LEVEL_ERROR, CODE)                       	            			\
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!PKCS11!", WPP_VAR(__LINE__))), 1 : 0                                	\
    ))                                                                                      					\
    WPP_TRACELEVEL_PKCS11_POST(TRACE_LEVEL_ERROR, CODE)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Отмена действия макросов
///////////////////////////////////////////////////////////////////////////////
#undef _NORETURN
