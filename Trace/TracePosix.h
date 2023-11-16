#pragma once
#include "TraceError.h"
#include <errno.h>

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
// Категория ошибок POSIX
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && _MSC_VER < 1600
class _generic_category : public std::error_category
{
    // имя категории ошибки 
    public: virtual const char* name() const noexcept { return "generic"; }

    // получить сообщение об ошибке
    public: virtual std::string message(int code) const 
    {
        // получить сообщение об ошибке
        char msg[4096]; strerror_s(msg, sizeof(msg), code); return msg; 
    }
};
namespace std {
inline const std::error_category& generic_category() 
{
    // категория ошибок POSIX
    static _generic_category category; return category; 
}
}
#endif 

#if defined __linux__
inline const std::error_category& posix_category() 
{
    // категория ошибок POSIX
    return std::system_category(); 
}
#else
inline const std::error_category& posix_category() 
{
    // категория ошибок POSIX
    return std::generic_category(); 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки POSIX
///////////////////////////////////////////////////////////////////////////////
class posix_error_code : public std::error_code
{
    // строковое представление по умолчанию
    private: char _code[16]; 

    // конструктор
    public: posix_error_code(int value) : std::error_code(value, posix_category()) 
    {
        // отформатировать код ошибки
        trace::snprintf(_code, sizeof(_code), "%d", value);
    } 
    // символическое описание ошибки
    public: const char* name() const
    {
    	switch (value())
   		{
    	case EPERM             : return "EPERM";            // EPERM       
    	case ENOENT            : return "ENOENT";           // ENOENT      
    	case ESRCH             : return "ESRCH";            // ESRCH       
    	case EINTR             : return "EINTR";            // EINTR       
    	case EIO               : return "EIO";              // EIO         
    	case ENXIO             : return "ENXIO";            // ENXIO       
    	case E2BIG             : return "E2BIG";            // E2BIG       
    	case ENOEXEC           : return "ENOEXEC";          // ENOEXEC     
    	case EBADF             : return "EBADF";            // EBADF       
    	case ECHILD            : return "ECHILD";           // ECHILD      
    	case EAGAIN            : return "EAGAIN";           // EAGAIN      
    	case ENOMEM            : return "ENOMEM";           // ENOMEM      
    	case EACCES            : return "EACCES";           // EACCES      
    	case EFAULT            : return "EFAULT";           // EFAULT      
    	case EBUSY             : return "EBUSY";            // EBUSY       
    	case EEXIST            : return "EEXIST";           // EEXIST      
    	case EXDEV             : return "EXDEV";            // EXDEV       
    	case ENODEV            : return "ENODEV";           // ENODEV      
    	case ENOTDIR           : return "ENOTDIR";          // ENOTDIR     
    	case EISDIR            : return "EISDIR";           // EISDIR      
    	case EINVAL            : return "EINVAL";           // EINVAL      
    	case ENFILE            : return "ENFILE";           // ENFILE      
    	case EMFILE            : return "EMFILE";           // EMFILE      
    	case ENOTTY            : return "ENOTTY";           // ENOTTY      
    	case EFBIG             : return "EFBIG";            // EFBIG       
    	case ENOSPC            : return "ENOSPC";           // ENOSPC      
    	case ESPIPE            : return "ESPIPE";           // ESPIPE      
    	case EROFS             : return "EROFS";            // EROFS       
    	case EMLINK            : return "EMLINK";           // EMLINK      
    	case EPIPE             : return "EPIPE";            // EPIPE       
    	case EDOM              : return "EDOM";             // EDOM        
    	case ERANGE            : return "ERANGE";           // ERANGE      
    	case EDEADLK           : return "EDEADLK";          // EDEADLK     
    	case ENAMETOOLONG      : return "ENAMETOOLONG";     // ENAMETOOLONG
    	case ENOLCK            : return "ENOLCK";           // ENOLCK      
    	case ENOSYS            : return "ENOSYS";           // ENOSYS      
    	case ENOTEMPTY         : return "ENOTEMPTY";        // ENOTEMPTY   
    	case EILSEQ            : return "EILSEQ";           // EILSEQ      
    	case 100               : return "EADDRINUSE";       // EADDRINUSE     
    	case 101               : return "EADDRNOTAVAIL";    // EADDRNOTAVAIL  
    	case 102               : return "EAFNOSUPPORT";     // EAFNOSUPPORT   
    	case 103               : return "EALREADY";         // EALREADY       
    	case 104               : return "EBADMSG";          // EBADMSG        
    	case 105               : return "ECANCELED";        // ECANCELED      
    	case 106               : return "ECONNABORTED";     // ECONNABORTED   
    	case 107               : return "ECONNREFUSED";     // ECONNREFUSED   
    	case 108               : return "ECONNRESET";       // ECONNRESET     
    	case 109               : return "EDESTADDRREQ";     // EDESTADDRREQ   
    	case 110               : return "EHOSTUNREACH";     // EHOSTUNREACH   
    	case 111               : return "EIDRM";            // EIDRM          
    	case 112               : return "EINPROGRESS";      // EINPROGRESS    
    	case 113               : return "EISCONN";          // EISCONN        
    	case 114               : return "ELOOP";            // ELOOP          
    	case 115               : return "EMSGSIZE";         // EMSGSIZE       
    	case 116               : return "ENETDOWN";         // ENETDOWN       
    	case 117               : return "ENETRESET";        // ENETRESET      
    	case 118               : return "ENETUNREACH";      // ENETUNREACH    
    	case 119               : return "ENOBUFS";          // ENOBUFS        
    	case 120               : return "ENODATA";          // ENODATA        
    	case 121               : return "ENOLINK";          // ENOLINK        
    	case 122               : return "ENOMSG";           // ENOMSG         
    	case 123               : return "ENOPROTOOPT";      // ENOPROTOOPT    
    	case 124               : return "ENOSR";            // ENOSR          
    	case 125               : return "ENOSTR";           // ENOSTR         
    	case 126               : return "ENOTCONN";         // ENOTCONN       
    	case 127               : return "ENOTRECOVERABLE";  // ENOTRECOVERABLE
    	case 128               : return "ENOTSOCK";         // ENOTSOCK       
    	case 129               : return "ENOTSUP";          // ENOTSUP        
    	case 130               : return "EOPNOTSUPP";       // EOPNOTSUPP     
    	case 131               : return "EOTHER";           // EOTHER         
    	case 132               : return "EOVERFLOW";        // EOVERFLOW      
    	case 133               : return "EOWNERDEAD";       // EOWNERDEAD     
    	case 134               : return "EPROTO";           // EPROTO         
    	case 135               : return "EPROTONOSUPPORT";  // EPROTONOSUPPORT
    	case 136               : return "EPROTOTYPE";       // EPROTOTYPE     
    	case 137               : return "ETIME";            // ETIME          
    	case 138               : return "ETIMEDOUT";        // ETIMEDOUT      
    	case 139               : return "ETXTBSY";          // ETXTBSY        
    	case 140               : return "EWOULDBLOCK";      // EWOULDBLOCK    
    	}
        return _code; 
    }
}; 
///////////////////////////////////////////////////////////////////////////////
// Исключение POSIX
///////////////////////////////////////////////////////////////////////////////
class posix_error : public trace::system_error<>
{
    // конструктор
    public: posix_error(const posix_error_code& code)

        // сохранить переданные параметры
        : trace::system_error<>(code) {}

    // конструктор
    public: posix_error(int code)

        // сохранить переданные параметры
        : trace::system_error<>(code, posix_category()) {}

    // выбросить исключение
    public: virtual _NORETURN void raise(const char* szFile, int line) const 
    { 
        // выбросить исключение
        trace(szFile, line); throw *this; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// Добавление способа форматирования
///////////////////////////////////////////////////////////////////////////////
inline void format_posix(trace::pprintf print, void* context, int level, va_list& args)
{
	// извлечь код ошибки
	posix_error_code error(va_arg(args, int)); 

	// получить символическое имя
	std::string name = error.name(); 

	// вывести символическое имя
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(POSIX, format_posix); 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок POSIX
///////////////////////////////////////////////////////////////////////////////
#define WPP_TRACELEVEL_POSIX_RAISE(FILE, LINE)              \
    posix_error(WPP_VAR(LINE)).raise(FILE, LINE);    

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_POSIX(LEVEL, ERRNO)       	    (int, ERRNO, WPP_CAST_BOOL, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_POSIX_PRE(LEVEL, ERRNO)      

// Проверка наличия трассировки
#define WPP_TRACELEVEL_POSIX_ENABLED(LEVEL, ERRNO)   	    WPP_VAR(__LINE__)

// Проверка наличия ошибки
#define WPP_TRACELEVEL_POSIX_POST(LEVEL, ERRNO)             \
    ; if (WPP_TRACELEVEL_POSIX_ENABLED(LEVEL, ERRNO)) {     \
         WPP_TRACELEVEL_POSIX_RAISE(__FILE__, __LINE__)     \
    }}

///////////////////////////////////////////////////////////////////////////////
// Определение трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_POSIX_LOGGER(LEVEL, ERRNO)   	    WppGetLogger(),
#else 
#define AE_CHECK_POSIX(ERRNO)                                                                     		    \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_POSIX(TRACE_LEVEL_ERROR, ERRNO), "ERROR %!POSIX!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_POSIX_PRE(TRACE_LEVEL_ERROR, ERRNO)                                            		    \
    (void)((                                                                                                \
        WPP_TRACELEVEL_POSIX_ENABLED(TRACE_LEVEL_ERROR, ERRNO)                                    		    \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!POSIX!", WPP_VAR(__LINE__))), 1 : 0                                \
    ))                                                                                            		    \
    WPP_TRACELEVEL_POSIX_POST(TRACE_LEVEL_ERROR, ERRNO)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Отмена действия макросов
///////////////////////////////////////////////////////////////////////////////
#undef _NORETURN
