#pragma once
#include <errno.h>

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ POSIX
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
inline const _error_category& posix_category() 
{
    // ��������� ������ POSIX
    return std::generic_category(); 
}
#else 
class _posix_category : public _error_category
{
    // �������� ��������� �� ������
    public: virtual std::string message(int code) const 
    {
        // �������� ��������� �� ������
        char msg[4096]; strerror_s(msg, sizeof(msg), code); return msg; 
    }
};
inline const _error_category& posix_category() 
{
    // ��������� ������ POSIX
    static _posix_category posix_category; return posix_category; 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� ������ POSIX
///////////////////////////////////////////////////////////////////////////////
class posix_error : public _error_code
{
    // �����������
    public: posix_error(const _error_category& category, int value) 
        
        // ��������� ���������� ���������
        : _error_code(value, category) {} 

    // �����������
    public: posix_error(int value) : _error_code(value, posix_category()) {} 

    // ������������� �������� ������
    public: std::string name() const
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
        // ��������������� ��� ������
        char str[16]; trace::snprintf(str, sizeof(str), "%d", value()); return str; 
    }
}; 
// ������� ������� ������
inline bool is_posix_error(int code) { return code != 0; }

///////////////////////////////////////////////////////////////////////////////
// ���������� POSIX
///////////////////////////////////////////////////////////////////////////////
class posix_exception : public system_exception
{
    // �����������
    public: posix_exception(const posix_error& error, const char* szFile, int line)

        // ��������� ���������� ���������
        : system_exception(error, szFile, line) {}

    // �����������
    public: posix_exception(int code, const char* szFile, int line)

        // ��������� ���������� ���������
        : system_exception(posix_error(code), szFile, line) {}

    // ��������� ����������
    public: virtual void raise() const { trace(); throw *this; }

    // ��������� ��� ��������� ������
    public: virtual void SetLastError() const { errno = code().value(); }
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ��������������
///////////////////////////////////////////////////////////////////////////////
inline void format_posix(trace::pprintf print, void* context, int level, va_list& args)
{
	// ������� ��� ������
	posix_error error(va_arg(args, int)); 

	// �������� ������������� ���
	std::string name = error.name(); 

	// ������� ������������� ���
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(POSIX, format_posix); 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� ���������
///////////////////////////////////////////////////////////////////////////////
namespace trace {
inline std::string GetPosixEnvironmentVariable(const char* szName)
{
#if !defined _MSC_VER
    // �������� ���������� ���������
    if (const char* szValue = getenv(szName)) return szValue;
#else 
    // �������� ����� ���������� �������
    char szBuffer[_MAX_ENV]; size_t cch = 0; 

    // �������� ���������� ���������
    if (getenv_s(&cch, szBuffer, sizeof(szBuffer), szName) == 0)
    {
	    // ��������� ���������� ���������
	    if (cch > 0) return std::string(szBuffer, cch - 1);
    }
#endif
    return std::string(); 
}
#if !defined _WIN32
inline std::string GetEnvironmentVariable(const char* szName)
{
    // �������� ���������� ���������
    return GetPosixEnvironmentVariable(szName); 
}
#endif 
}
