#pragma once
///////////////////////////////////////////////////////////////////////////////
// ����������� nullptr
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && _MSC_VER < 1700
#if !defined _MANAGED || _MANAGED == 0
#define nullptr 0
#endif
#endif

///////////////////////////////////////////////////////////////////////////////
// ����������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
#include <wmistr.h>                     // ����������� WMI
#include <evntrace.h>                   // ����������� ETW
#else 
#define TRACE_LEVEL_NONE            0   // ���������� �����������
#define TRACE_LEVEL_CRITICAL        1   // ����������� ������
#define TRACE_LEVEL_ERROR           2   // ������
#define TRACE_LEVEL_WARNING         3   // ��������������
#define TRACE_LEVEL_INFORMATION     4   // ����������
#define TRACE_LEVEL_VERBOSE         5   // ���������������� ����������
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ����� �������
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER
#define __FUNC__    __FUNCSIG__
#else 
#define __FUNC__    __func__
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������ ����������� �������
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER
#define WPP_NOINLINE        __declspec(noinline)
#else 
#define WPP_NOINLINE        __attribute__((noinline)) 
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� ����������� ������
///////////////////////////////////////////////////////////////////////////////
#define WPP_STR(      x)          # x
#define WPP_STRINGIZE(x)    WPP_STR(x)

///////////////////////////////////////////////////////////////////////////////
// �������� ����������� ����� ����������
///////////////////////////////////////////////////////////////////////////////
#define WPP_GLUE(x, y)      x ## y
#define WPP_VAR(LINE )      WPP_GLUE(Trace, LINE)

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� �����������
///////////////////////////////////////////////////////////////////////////////
#if !defined WPP_CONTROL_NAME
#error [Trace.h] The WPP_CONTROL_NAME should be defined prior to including Trace.h
#endif

// ������� ��� ����������
#if !defined __COMPNAME__
#define __COMPNAME__ WPP_CONTROL_NAME
#endif 

// ����������� �������������� �����������
#if !defined WPP_STATIC_LIB_GUIDS
#define WPP_STATIC_LIB_GUIDS
#endif 

// ����������� ��������������� �����������
#if defined WPP_CONTROL_GUID
#define WPP_CONTROL_GUIDS                                           \
    WPP_DEFINE_CONTROL_GUID(WPP_CONTROL_NAME, WPP_CONTROL_GUID,     \
        WPP_DEFINE_BIT(ALL)                                         \
    )                                                               \
    WPP_STATIC_LIB_GUIDS
#endif
// ��������� ������������� ����� ����������
#define WPP_COMPNAME WPP_STRINGIZE(__COMPNAME__)

///////////////////////////////////////////////////////////////////////////////
// ������������� ������������ �����
///////////////////////////////////////////////////////////////////////////////
#include <stdarg.h>         // ������� � ���������� ������ ����������
#include <string.h>         // ��������� ������� 

#if !defined _NTDDK_
#include <stdlib.h>         // ������� ������ ����������
#include <string>           // ��������� ������� C++
#if _HAS_CXX17 == 1
#include <string_view>      // ��������� ���������� C++17
#endif
#if defined _WIN32
#include <winternl.h>		// �������������� ����������� Windows 
#include <sddl.h>			// ������� ������������ Windows
#include <objbase.h>        // ����������� COM
#endif 
#if defined __linux__
#include <unistd.h>         // ����������� Unix
#include <pthread.h>        // ���������� �������
#endif 
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� ����������� ���������� � ������ ������� TraceMessageVa. 
// � ��������� ������� ����� evntrace.h stdcall-������� TraceMessageVa 
// ��������� ��� �������� ���������� � ������, ��� ��� ������������� 
// ������������ �� ��������� ���������� __cdecl �������� � ������������ 
// ������������� ��������������� ����� ������� � ��������� ����� ��� 
// ���������� �������. 
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS && !defined _NTDDK_
#if defined _MSC_VER && !defined _WIN64
#pragma comment(linker, "/alternatename:_TraceMessageVa=_TraceMessageVa@24")

// ������� ���������� �������� �������
typedef ULONG (WINAPI *PFN_TRACE_MESSAGE_VA)(TRACEHANDLE, ULONG, LPCGUID, USHORT, va_list);

// ������� ������� �����������
inline ULONG WINAPI CallTraceMessageVa(TRACEHANDLE LoggerHandle,
    ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, va_list MessageArgList)
{
    // ��������� �������������� ����
    PFN_TRACE_MESSAGE_VA pfn = (PFN_TRACE_MESSAGE_VA)::TraceMessageVa; 

    // ��������� �����������
    return (*pfn)(LoggerHandle, MessageFlags, MessageGuid, MessageNumber, MessageArgList); 
}
#else 
// ������� ������� �����������
inline ULONG WINAPI CallTraceMessageVa(TRACEHANDLE LoggerHandle,
    ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, va_list MessageArgList)
{
    // ��������� �����������
    return ::TraceMessageVa(LoggerHandle, 
        MessageFlags, (LPGUID)MessageGuid, MessageNumber, MessageArgList
    ); 
}
#endif 
#endif

// �� ��������� ������������ ����������� ����������� � .tmc-������ ��� ������
// Release-������ ���������� ������� �������������� ������� ����� ����� 
// ���������� /OPT:REF. 

///////////////////////////////////////////////////////////////////////////////
// ����������� ����� �������������� �������
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(.*s , WPP_LOGCPPVEC, const trace::_str &, ItemPString,  "s",  str, 0);
// DEFINE_CPLX_TYPE(.*hs, WPP_LOGCPPVEC, const trace::_str &, ItemPString,  "s",  str, 0);
// DEFINE_CPLX_TYPE(.*ls, WPP_LOGCPPVEC, const trace::_wstr&, ItemPWString, "s", wstr, 0);
// DEFINE_CPLX_TYPE(.*ws, WPP_LOGCPPVEC, const trace::_wstr&, ItemPWString, "s", wstr, 0);
// end_wpp

namespace trace { 
struct _str { const char* _sz; size_t _cch;
    
    // �����������
    _str(const char* sz, size_t cch) : _sz(sz), _cch(cch) {} 

    // ����� ������
    const char* data() const { return _sz; }

    // ������ ������
    size_t size() const { return _cch; }
};
struct _wstr { const wchar_t* _sz; size_t _cch;
    
    // �����������
    _wstr(const wchar_t* sz, size_t cch) : _sz(sz), _cch(cch) {}

    // ����� ������
    const wchar_t* data() const { return _sz; }

    // ������ ������
    size_t size() const { return _cch; }
};
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������� (���������� ���������)
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
namespace trace {
extern std::string GetEnvironmentVariable(const char*);
class ControlParameters
{ 
	// �����������
	public: ControlParameters() { Update(); } private: std::string prefix;

    // �������� �������� ����������
    public: void Update() { prefix = GetEnvironmentVariable("TRACE_FORMAT_PREFIX"); }
	// �������� ��������
	public: const char* DebugPrefix() const 
	{ 
		// �������� ��������
		return (prefix.length() != 0) ? prefix.c_str() : nullptr; 
	}
};
#if !defined WPP_CONTROL_GUIDS 
inline const ControlParameters* GetControlParameters() 
{ 
	// �������� ������ ������ ��������
	static ControlParameters parameters; return &parameters;
}
#else 
// �������� ��������� �����������
const ControlParameters* GetControlParameters(); 
#endif 
}
#endif

///////////////////////////////////////////////////////////////////////////////
// ���������� ������������ �����
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
#include "TraceUTF.h"       // �������������� ���������
#endif 
#include "TraceFormat.h"    // �������������� �����
#include "TraceDebug.h"     // ����� ��������� � ��������

///////////////////////////////////////////////////////////////////////////////
// ��������������� ���������� �������
///////////////////////////////////////////////////////////////////////////////
void WppTraceStringA(int level, const char   * sz, size_t cch = -1); 
void WppTraceStringW(int level, const wchar_t* sz, size_t cch = -1); 

///////////////////////////////////////////////////////////////////////////////
// ����� ��������� � ��������. ��������� ���������� WPP ��������� ��� 
// ������ ������� WppDebug(n, MsgArgs), ��� n - ���������� �����, � 
// MsgArgs - ����������� � ������� ������ ������ �������������� � �� 
// ���������. � ������������ ���������� ��������� ���������� ����� 
// ������������ ��������� � ������� ����������� TRACE_LEVEL_INFORMATION. 
///////////////////////////////////////////////////////////////////////////////
inline void WppDebugPrintV(int level, const char* szFile, 
    int line, const char* szFunction, const char* szFormat, va_list& args)
{
    // �������� �������� �������������� �������
    void (*pfnA)(int, const char   *, size_t) = &WppTraceStringA; (*pfnA)(0, nullptr, 0); 
    void (*pfnW)(int, const wchar_t*, size_t) = &WppTraceStringW; (*pfnW)(0, nullptr, 0);

#if !defined _NTDDK_ && defined WPP_CONTROL_GUIDS
	// ��������� ������������� ������
	if (level == TRACE_LEVEL_VERBOSE) return; 
#endif 
	// ��������� ������������� ������
	if (level == TRACE_LEVEL_NONE) return; 

    // �������� ��������� ���������
    trace::DebugPrintV(WPP_COMPNAME, "ALL", level, 
        szFile, line, szFunction, false, szFormat, args
	); 
}

inline void WppDebugPrint(int level, const char* szFile, 
    int line, const char* szFunction, const char* szFormat, ...)
{
    // ������� �� ���������� ����� ����������
    va_list args; va_start(args, szFormat); 

    // �������� ��������� ���������
	WppDebugPrintV(level, szFile, line, szFunction, szFormat, args); 	

	// ���������� ���������� �������
	va_end(args);
}
// ���������� ������������� ���������� 
#define WPP_DEBUG_PRINT(...)	WppDebugPrint(	\
	TRACE_LEVEL_INFORMATION,                    \
	__FILE__, __LINE__, __FUNC__, __VA_ARGS__	\
)
// ��������������� ��������� ����������
#define WppDebug(n, MsgArgs) WPP_DEBUG_PRINT MsgArgs

///////////////////////////////////////////////////////////////////////////////
// ���������� ����� ����������� ���� ATRACE(TRACELEVEL,...,MSG,...) ������������ 
// ��������� ����������: 
// WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_<XXX>(...), MSG,...)
// WPP_TRACELEVEL_<XXX>_PRE(TRACELEVEL, ...)
// ((
//     WPP_TRACELEVEL_<XXX>_ENABLED(TRACELEVEL, ...)
//     ? WPP_INVOKE_WPP_DEBUG((MSG,...)), WPP_SF_<SIG>(...), 1 : 0
// ))
// WPP_TRACELEVEL_<XXX>_POST(TRACELEVEL, ...)
///////////////////////////////////////////////////////////////////////////////
// 1) ������ WPP_LOG_ALWAYS ������������ ��� ��������������� ������ ��������� 
//    � ��������. ��� ���������� ��� ���������, ������������ ��������
//    WPP_EX_TRACELEVEL_<XXX>, � ����� ������ �������������� � �� ���������. 
//    ���������, ������������ �������� WPP_EX_TRACELEVEL_<XXX>, ������������ 
//    ��� �������� ������������� ������ ���������, � ����� ����������� ������ 
//    �����������, ������������� � ���������. ���� ���������� ������� ����� 
//    TRACE_LEVEL_NONE, �� ����� � �������� �� ������������. � ��������� ������, 
//    a) � ������ ���� ����� � �������� �������������� � ������������ �� 
//       ��������� ��������: 
//       TRACE_LEVEL_CRITICAL    -> DPFLTR_ERROR_LEVEL;
//       TRACE_LEVEL_ERROR       -> DPFLTR_ERROR_LEVEL;
//       TRACE_LEVEL_WARNING     -> DPFLTR_WARNING_LEVEL;
//       TRACE_LEVEL_INFORMATION -> DPFLTR_INFO_LEVEL;
//       TRACE_LEVEL_VERBOSE     -> DPFLTR_TRACE_LEVEL;
//    b) � ������ ������������ ������� ����������� ������������ � ����� 
//       � �������� ������������ ������, �� ����������� ������ 
//       TRACE_LEVEL_VERBOSE ��� ������� ETW-�����������. 
// 2) ������ WPP_EX_TRACELEVEL_<XXX>, ��� ��� ������� ����, ������������ 
//    ��� �������� �������������� ���������� ������� WPP_LOG_ALWAYS. ����� 
//    ��������� ���������� ������ ���� ������� �����������, ������������ 
//    � ���������. 
// 3) ������ WPP_TRACELEVEL_<XXX>_PRE ������������ ��� ���������� 
//    �������������� ��������������� �������� �� ����������������� ������� 
//    �����������. 
// 4) ������ WPP_TRACELEVEL_<XXX>_ENABLED ��������� ������������� 
//    ���������� ����������� (��������, ������������ ������ ����������� 
//    ������������� ������ ����������� � ������). 
// 5) ������ WPP_INVOKE_WPP_DEBUG ����������� ������ ���������� ������ 
//    ��������������� ����� ������������, ��������� � �������� ���������� 
//    ������ �������������� � �� ��������� � ������������ ����� ������ 
//    WPP_DEBUG. ���� ������ WPP_DEBUG �� ���������, �� ������ 
//    WPP_INVOKE_WPP_DEBUG ������ �� ���������. 
// 6) ������� WPP_SF_<SIG> �������� ���������� �������� ��� ������� 
//    ����������� WPP_TRACE, ������� ��������������� � ��������� 
//    ����������� ����������. �� ��������� � ������ ������������
//    ������ WPP_TRACE ������������ � ����� ������� TraceMessage. 
// 7) ������ WPP_TRACELEVEL_<XXX>_POST ������������ ��� ���������� 
//    �������������� ����������� ��������. 
///////////////////////////////////////////////////////////////////////////////
// ��������� � ����������. 
///////////////////////////////////////////////////////////////////////////////
// 1) ��������� ������ �������������� � �� ��������� �� ���� ������� ��������
//    (Debug � Release) ���������� ������ ������� WPP_LOG_ALWAYS, �� 
//    ����� � �������� ���������������� ������ ����� ���� ������ ��� 
//    ���������� ������� WPP_LOG_ALWAYS (������� ���������� ���������� 
//    � ������� WPP_LOG_ALWAYS �� ���������������, ��������� ��� ����� 
//    ���������� ����������� ��������� ����� � ���������� ������ ����������, 
//    ��� �� �������������� � ������ ������� Visual Studio, ��������, 2008). 
// 2) ��������� ��� �������� ���������� ������ ����� ���������� ������� 
//    �������������� ������������ �������� �������� (����) ������, ������� 
//    ����� ������������ � ����� �������, �� ������ WPP_LOG_ALWAYS ������ 
//    ��������� ��� �� ��������� ���������� ��� ������������ ������������� 
//    ��������� ��������� ����������, � �� ���������� ��������� �������, 
//    ����������� � ������ ������ �������. 
// 3) ��� �������� ������������� ������ ������������������ ��������� � 
//    �������� ������� WPP_LOG_ALWAYS ������ ������������ ������� ��� 
//    ������ ������ �������� ������������ ������ (��������, ������
//    WPP_TRACELEVEL_<XXX>_ENABLED). � ������� ���������� ��� ����������� 
//    ��������� ������� WPP_LOG_ALWAYS ������ ������� �������� ������������, 
//    ������� ����� ���������� ������� ������ ������� WPP_LOG_ALWAYS.
// 4) ��������� �.1)-3), ������ WPP_EX_TRACELEVEL_<XXX> ������ �������� 
//    ������� WPP_LOG_ALWAYS ��� ������� 4 ���������: 
//    a) ��� ����������, � ������� ������ ����������� ���������� 
//       ����������� �������� (��� ��� ������� ������); 
//    b) �������� ���������� ������������ ���������; 
//    �) ��� �������, ����������� ������������ ������; 
//    d) ������� �����������, ����������� ����������. 
// 5) ���� � �������� ���������� ������� WPP_EX_TRACELEVEL_<XXX> ������� 
//    ���������� ��������� ����� ������� ��� �������������� ������������, 
//    �� ���������� Microsoft �������� (�� � ������������ �� ����������) 
//    �� "���������" ��������� � ���������������� ��������� ������� 
//    WPP_LOG_ALWAYS, � � "�����������" ���� ���� ��������� (�.�. ��� 
//    ���������) ������c� �� ����� ������� ��������� �������. ������� 
//    ��� ����������� ������������� ��������� ���������� ����������� 
//    ��������� ����������� �� ���������� �����: 
//    a) ������ WPP_EX_TRACELEVEL_<XXX> ���������� ��������� ��������� � 
//       ������� ������� (��� ������������� �������� ���������� ���������); 
//    b) ������������ 4 ��������� ������� ���������� ����������: 
//       #define WPP_LOG_EXTRACT_TYPE( TYPE, VALUE, CHECK, LEVEL) TYPE
//       #define WPP_LOG_EXTRACT_VALUE(TYPE, VALUE, CHECK, LEVEL) VALUE
//       #define WPP_LOG_EXTRACT_CHECK(TYPE, VALUE, CHECK, LEVEL) CHECK
//       #define WPP_LOG_EXTRACT_LEVEL(TYPE, VALUE, CHECK, LEVEL) LEVEL 
//    c) ��������� ��������� ������� ����������� � ������ WPP_LOG_ALWAYS 
//       ��� ������ (����� �������� ���������������� ���������). ������ �� 
//       ������������� ��� ����������� ���������� ������� 
//       WPP_EX_TRACELEVEL_<XXX>. 
///////////////////////////////////////////////////////////////////////////////
#if !defined WPP_CONTROL_GUIDS 
#ifdef WPP_DEBUG
#define WPP_INVOKE_WPP_DEBUG(MsgArgs) WPP_DEBUG(MsgArgs)
#else
#define WPP_INVOKE_WPP_DEBUG(MsgArgs) (void)0
#endif
#endif

// ���������� ��������� ���������� 
#define WPP_LOG_EXTRACT_TYPE( TYPE, VALUE, CHECK, LEVEL)    TYPE
#define WPP_LOG_EXTRACT_VALUE(TYPE, VALUE, CHECK, LEVEL)    VALUE
#define WPP_LOG_EXTRACT_CHECK(TYPE, VALUE, CHECK, LEVEL)    CHECK
#define WPP_LOG_EXTRACT_LEVEL(TYPE, VALUE, CHECK, LEVEL)    LEVEL

// ����� � ��������
#define WPP_LOG_ALWAYS(ARGS, ...)                {      \
    WPP_LOG_EXTRACT_TYPE ARGS WPP_VAR(__LINE__) =       \
        WPP_LOG_EXTRACT_VALUE ARGS;                     \
    if (WPP_LOG_EXTRACT_CHECK ARGS(WPP_VAR(__LINE__)))  \
    WppDebugPrint(										\
        WPP_LOG_EXTRACT_LEVEL ARGS,                  	\
        __FILE__, __LINE__, __FUNC__,                	\
        __VA_ARGS__                                     \
    ); 

///////////////////////////////////////////////////////////////////////////////
// ��������������� ������� ����������� ��� �������������� ��������� ���� 
// ��������� ������ � ������� (��� ����������� � ������ ������� ������� 
// TraceMessage)
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS && !defined _NTDDK_
inline DWORD WppTraceMessage(
    IN TRACEHANDLE hLogger, IN ULONG messageFlags, 
    IN LPCGUID messageGuid, IN USHORT messageNumber, ...)
{
    // ��������� ��� ��������� ������
    DWORD lastError = ::GetLastError();

    // ������� �� ���������� ����� ����������
    va_list args; va_start(args, messageNumber);

    // ��������� ����������� ������� �����������
    DWORD code = CallTraceMessageVa(
        hLogger, messageFlags, messageGuid, messageNumber, args
    );
    // ������������ ��� ������
    va_end(args); ::SetLastError(lastError); return code; 
}
// ������� ����������� � ��������� ������� 
#define WPP_REGISTER_TRACE_GUIDS    WppRegisterTraceGuids
#define WPP_UNREGISTER_TRACE_GUIDS  WppUnregisterTraceGuids
#define WPP_PRIVATE_ENABLE_CALLBACK WppNotificationCallback
#define WPP_TRACE                   WppTraceMessage
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� ����������� ����������� ����� ������� ATRACE(TRACELEVEL, MSG, ...), 
// ������ �������� ������� (������ ��������������) ������ ���� �������� �� 
// ����� ����������. 
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC ATRACE(TRACELEVEL, MSG, ...);
// end_wpp

inline bool wpp_dummy(int) { return true; }

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL(LEVEL)            (int, 0, wpp_dummy, LEVEL)

// ���������� �������������� ��������
#define WPP_TRACELEVEL_PRE(LEVEL)           (void)WPP_VAR(__LINE__);

// ���������� �������������� ��������
#define WPP_TRACELEVEL_POST(LEVEL)          ;}

#ifdef WPP_CONTROL_GUIDS

// ��������� ������ �����������
#define WPP_TRACELEVEL_LOGGER(LEVEL)        WppGetLogger(),

// �������� ������������ ����������� ��� ���������� ������
#define WPP_TRACELEVEL_ENABLED(LEVEL)       (WppGetControl()->Level >= LEVEL)

#else 

// �������� ������������ �����������
#define WPP_TRACELEVEL_ENABLED(LEVEL)       (1) 

// ����� �����������
#define ATRACE(LEVEL, ...)                                     \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(LEVEL), __VA_ARGS__)      \
    WPP_TRACELEVEL_PRE(LEVEL)                                  \
    (void)((                                                   \
        WPP_TRACELEVEL_ENABLED(LEVEL)                          \
        ? WPP_INVOKE_WPP_DEBUG((__VA_ARGS__)), 1 : 0           \
    ))                                                         \
    WPP_TRACELEVEL_POST(LEVEL)                                       
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� ������������� ������ � �������� name()
///////////////////////////////////////////////////////////////////////////////
#define WPP_LOG_CPPNAME(x)     WPP_LOGPAIR((x).name().length() + 1, (x).name().c_str())

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ POSIX
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(POSIX, WPP_LOG_CPPNAME, const posix_error&, ItemString, "s", posix , 0);
// FUNC AE_CHECK_POSIX{TRACELEVEL=TRACE_LEVEL_ERROR}(POSIX);
// USESUFFIX(AE_CHECK_POSIX, "ERROR %!POSIX!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_POSIX(LEVEL, ERRNO)       	(int, ERRNO, is_posix_error, LEVEL)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_POSIX_PRE(LEVEL, ERRNO)      

// �������� ������� �����������
#define WPP_TRACELEVEL_POSIX_ENABLED(LEVEL, ERRNO)   	                \
    is_posix_error(WPP_VAR(__LINE__))

// ����������� ����������
#define WPP_TRACELEVEL_POSIX_RAISE(FILE, LINE)                          \
    posix_exception(WPP_VAR(LINE), FILE, LINE).raise();    

// �������� ������� ������
#define WPP_TRACELEVEL_POSIX_POST(LEVEL, ERRNO)                         \
    ; if (WPP_TRACELEVEL_POSIX_ENABLED(LEVEL, ERRNO)) {                 \
         WPP_TRACELEVEL_POSIX_RAISE(__FILE__, __LINE__)                 \
    }}

// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_POSIX_LOGGER(LEVEL, ERRNO)   	WppGetLogger(),
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
// ����������� ������ NTSTATUS
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_NTSTATUS{TRACELEVEL=TRACE_LEVEL_ERROR}(NTSTATUS);
// USESUFFIX(AE_CHECK_NTSTATUS, "ERROR %!STATUS!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_NTSTATUS(LEVEL, STATUS)        (NTSTATUS, STATUS, is_native_error, LEVEL)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_NTSTATUS_PRE(LEVEL, STATUS)       

// �������� ������� �����������
#define WPP_TRACELEVEL_NTSTATUS_ENABLED(LEVEL, STATUS)                      \
    is_native_error(WPP_VAR(__LINE__))

// ����������� ����������
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_NTSTATUS_RAISE(FILE, LINE)                           \
    windows_exception(native_error(WPP_VAR(LINE)), FILE, LINE).trace();     \
    throw gcnew System::ComponentModel::Win32Exception(                     \
        native_error(WPP_VAR(LINE)).value()                 		        \
    );  
#else
#define WPP_TRACELEVEL_NTSTATUS_RAISE(FILE, LINE)                           \
    windows_exception(native_error(WPP_VAR(LINE)), FILE, LINE).raise();
#endif 

// �������� ������� ������
#define WPP_TRACELEVEL_NTSTATUS_POST(LEVEL, STATUS)                         \
    ; if (WPP_TRACELEVEL_NTSTATUS_ENABLED(LEVEL, STATUS)) {                 \
         WPP_TRACELEVEL_NTSTATUS_RAISE(__FILE__, __LINE__)                  \
    }}

// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_NTSTATUS_LOGGER(LEVEL, STATUS)    WppGetLogger(),
#else 
#define AE_CHECK_NTSTATUS(STATUS)                                                                                \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_NTSTATUS(TRACE_LEVEL_ERROR, STATUS), "ERROR %!STATUS!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_NTSTATUS_PRE(TRACE_LEVEL_ERROR, STATUS)                                                       \
    (void)((                                                                                                     \
        WPP_TRACELEVEL_NTSTATUS_ENABLED(TRACE_LEVEL_ERROR, STATUS)                                               \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!STATUS!", WPP_VAR(__LINE__))), 1 : 0                                    \
    ))                                                                                                           \
    WPP_TRACELEVEL_NTSTATUS_POST(TRACE_LEVEL_ERROR, STATUS)
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ HRESULT
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_HRESULT{TRACELEVEL=TRACE_LEVEL_ERROR}(HRESULT);
// USESUFFIX(AE_CHECK_HRESULT, "ERROR %!HRESULT!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_HRESULT(LEVEL, HR)        		(HRESULT, HR, is_hresult_error, LEVEL)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_HRESULT_PRE(LEVEL, HR)       

// �������� ������� �����������
#define WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)   		                \
    is_hresult_error(WPP_VAR(__LINE__))

// ����������� ����������
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_HRESULT_RAISE(FILE, LINE)                            \
    windows_exception(hresult_error(WPP_VAR(LINE)), FILE, LINE).trace();    \
    throw gcnew System::ComponentModel::Win32Exception(WPP_VAR(LINE));  
#else
#define WPP_TRACELEVEL_HRESULT_RAISE(FILE, LINE)                            \
    windows_exception(hresult_error(WPP_VAR(LINE)), FILE, LINE).raise();
#endif 

// �������� ������� ������
#define WPP_TRACELEVEL_HRESULT_POST(LEVEL, HR)                              \
    ; if (WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)) {                      \
         WPP_TRACELEVEL_HRESULT_RAISE(__FILE__, __LINE__)                   \
    }}

// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_HRESULT_LOGGER(LEVEL, HR)    		WppGetLogger(),
#else 
#define AE_CHECK_HRESULT(HR)                                                                                  \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_HRESULT(TRACE_LEVEL_ERROR, HR), "ERROR %!HRESULT!", WPP_VAR(__LINE__))   \
    WPP_TRACELEVEL_HRESULT_PRE(TRACE_LEVEL_ERROR, HR)                                                         \
    (void)((                                                                                                  \
        WPP_TRACELEVEL_HRESULT_ENABLED(TRACE_LEVEL_ERROR, HR)                                                 \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!HRESULT!", WPP_VAR(__LINE__))), 1 : 0                                \
    ))                                                                                                        \
    WPP_TRACELEVEL_HRESULT_POST(TRACE_LEVEL_ERROR, HR)                                  
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ Windows 
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_WINERROR{TRACELEVEL=TRACE_LEVEL_ERROR}(WINERROR);
// USESUFFIX(AE_CHECK_WINERROR, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_WINERROR(LEVEL, ERROR)        (DWORD, ERROR, is_windows_error, LEVEL)

// ���������� ���� ������
#define WPP_TRACELEVEL_WINERROR_PRE(LEVEL, ERROR)       

// �������� ������� �����������
#define WPP_TRACELEVEL_WINERROR_ENABLED(LEVEL, ERROR)                       \
    is_windows_error(WPP_VAR(__LINE__))

// ����������� ����������
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_WINERROR_RAISE(FILE, LINE)                           \
    windows_exception(windows_error(WPP_VAR(LINE)), FILE, LINE).trace();    \
    throw gcnew System::ComponentModel::Win32Exception(                     \
        HRESULT_FROM_WIN32(WPP_VAR(LINE))                                   \
    );
#else
#define WPP_TRACELEVEL_WINERROR_RAISE(FILE, LINE)                           \
    windows_exception(windows_error(WPP_VAR(LINE)), FILE, LINE).raise();
#endif 

// �������� ������� ������
#define WPP_TRACELEVEL_WINERROR_POST(LEVEL, ERROR)                          \
    ; if (WPP_TRACELEVEL_WINERROR_ENABLED(LEVEL, ERROR)) {                  \
         WPP_TRACELEVEL_WINERROR_RAISE(__FILE__, __LINE__)                  \
    }}

// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_WINERROR_LOGGER(LEVEL, ERROR)    WppGetLogger(),
#else 
#define AE_CHECK_WINERROR(ERROR)                                                                                     \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_WINERROR(TRACE_LEVEL_ERROR, ERROR), "ERROR %!WINERROR!", WPP_VAR(__LINE__))     \
    WPP_TRACELEVEL_WINERROR_PRE(TRACE_LEVEL_ERROR, ERROR)                                                            \
    (void)((                                                                                                         \
        WPP_TRACELEVEL_WINERROR_ENABLED(TRACE_LEVEL_ERROR, ERROR)                                                    \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!WINERROR!", WPP_VAR(__LINE__))), 1 : 0                                      \
    ))                                                                                                               \
    WPP_TRACELEVEL_WINERROR_POST(TRACE_LEVEL_ERROR, ERROR)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ WinAPI
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_WINAPI{TRACELEVEL=TRACE_LEVEL_ERROR}(WINAPI);
// USESUFFIX(AE_CHECK_WINAPI, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_WINAPI(LEVEL, RET)            (DWORD, (RET) ? ERROR_SUCCESS : ::GetLastError(), is_windows_error, LEVEL)

// ���������� �������������� ��������
#define WPP_TRACELEVEL_WINAPI_PRE(LEVEL, RET)       

// �������� ������� �����������
#define WPP_TRACELEVEL_WINAPI_ENABLED(LEVEL, RET)                           \
    is_windows_error(WPP_VAR(__LINE__))

// �������� ������� ������
#define WPP_TRACELEVEL_WINAPI_POST(LEVEL, RET)                              \
    ; if (WPP_TRACELEVEL_WINAPI_ENABLED(LEVEL, RET)) {                      \
         WPP_TRACELEVEL_WINERROR_RAISE(__FILE__, __LINE__)                  \
    }}

// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_WINAPI_LOGGER(LEVEL, RET)        WppGetLogger(),
#else 
#define AE_CHECK_WINAPI(RET)                                                                                     \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_WINAPI(TRACE_LEVEL_ERROR, RET), "ERROR %!WINERROR!", WPP_VAR(__LINE__))     \
    WPP_TRACELEVEL_WINAPI_PRE(TRACE_LEVEL_ERROR, RET)                                                            \
    (void)((                                                                                                     \
        WPP_TRACELEVEL_WINAPI_ENABLED(TRACE_LEVEL_ERROR, RET)                                                    \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!WINERROR!", WPP_VAR(__LINE__))), 1 : 0                                  \
    ))                                                                                                           \
    WPP_TRACELEVEL_WINAPI_POST(TRACE_LEVEL_ERROR, RET)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ WinSock
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_WINSOCK{TRACELEVEL=TRACE_LEVEL_ERROR}(WINSOCK);
// USESUFFIX(AE_CHECK_WINSOCK, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_WINSOCK(LEVEL, CODE)            (DWORD, ((CODE) >= 0) ? ERROR_SUCCESS : ::WSAGetLastError(), is_windows_error, LEVEL)

// ���������� �������������� ��������
#define WPP_TRACELEVEL_WINSOCK_PRE(LEVEL, CODE)       

// �������� ������� �����������
#define WPP_TRACELEVEL_WINSOCK_ENABLED(LEVEL, CODE)                         \
    is_windows_error(WPP_VAR(__LINE__))

// �������� ������� ������
#define WPP_TRACELEVEL_WINSOCK_POST(LEVEL, CODE)                            \
    ; if (WPP_TRACELEVEL_WINSOCK_ENABLED(LEVEL, CODE)) {                    \
         WPP_TRACELEVEL_WINERROR_RAISE(__FILE__, __LINE__)                  \
    }}

// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_WINSOCK_LOGGER(LEVEL, CODE)        WppGetLogger(),
#else 
#define AE_CHECK_WINSOCK(CODE)                                                                                 	\
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_WINSOCK(TRACE_LEVEL_ERROR, CODE), "ERROR %!WINERROR!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_WINSOCK_PRE(TRACE_LEVEL_ERROR, CODE)                                                         \
    (void)((                                                                                                    \
        WPP_TRACELEVEL_WINSOCK_ENABLED(TRACE_LEVEL_ERROR, CODE)                                                 \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!WINERROR!", WPP_VAR(__LINE__)), 1 : 0                                	\
    ))                                                                                                          \
    WPP_TRACELEVEL_WINSOCK_POST(TRACE_LEVEL_ERROR, CODE)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������� ������ 
// (�������� ���������� ��� WinAPI � ���� ���������� ��� POSIX)
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_SYSAPI{TRACELEVEL=TRACE_LEVEL_ERROR}(SYSAPI);
// USESUFFIX(AE_CHECK_SYSAPI, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

#if defined WPP_CONTROL_GUIDS

// ��������� ������ �����������
#define WPP_TRACELEVEL_SYSAPI_LOGGER(LEVEL, RET)    WPP_TRACELEVEL_WINAPI_LOGGER(LEVEL, RET)

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_SYSAPI(LEVEL, RET)        WPP_EX_TRACELEVEL_WINAPI(LEVEL, RET)

// ���������� ���� ������
#define WPP_TRACELEVEL_SYSAPI_PRE(LEVEL, RET)       WPP_TRACELEVEL_WINAPI_PRE(LEVEL, RET)

// �������� ������� �����������
#define WPP_TRACELEVEL_SYSAPI_ENABLED(LEVEL, RET)   WPP_TRACELEVEL_WINAPI_ENABLED(LEVEL, RET)

// �������� ������� ������
#define WPP_TRACELEVEL_SYSAPI_POST(LEVEL, RET)      WPP_TRACELEVEL_WINAPI_POST(LEVEL, RET)

#elif defined _WIN32
#define AE_CHECK_SYSAPI(RET)    AE_CHECK_WINAPI(RET)
#else 
#define AE_CHECK_SYSAPI(CODE)   AE_CHECK_POSIX(CODE)
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ���������� ������ 
// (� ��������� ���� ��� Windows � ���� ��� POSIX)
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_RAISE_GENERIC{TRACELEVEL=TRACE_LEVEL_ERROR}(POSIX, WINERROR);
// USESUFFIX(AE_RAISE_GENERIC, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

#if defined WPP_CONTROL_GUIDS

// ��������� ������ �����������
#define WPP_TRACELEVEL_POSIX_WINERROR_LOGGER(LEVEL, ERRNO, ERROR)    WPP_TRACELEVEL_WINERROR_LOGGER(LEVEL, ERROR)

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_POSIX_WINERROR(LEVEL, ERRNO, ERROR)        WPP_EX_TRACELEVEL_WINERROR(LEVEL, ERROR)

// ���������� ���� ������
#define WPP_TRACELEVEL_POSIX_WINERROR_PRE(LEVEL, ERRNO, ERROR)       WPP_TRACELEVEL_WINERROR_PRE(LEVEL, ERROR)

// �������� ������� �����������
#define WPP_TRACELEVEL_POSIX_WINERROR_ENABLED(LEVEL, ERRNO, ERROR)   WPP_TRACELEVEL_WINERROR_ENABLED(LEVEL, ERROR)

// �������� ������� ������
#define WPP_TRACELEVEL_POSIX_WINERROR_POST(LEVEL, ERRNO, ERROR)      WPP_TRACELEVEL_WINERROR_POST(LEVEL, ERROR)

#elif defined _WIN32
#define AE_RAISE_GENERIC(ERRNO, ERROR)   AE_CHECK_WINERROR(ERROR)
#else 
#define AE_RAISE_GENERIC(ERRNO, ERROR)   AE_CHECK_POSIX(ERRNO)
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ COM
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_COM{TRACELEVEL=TRACE_LEVEL_ERROR}(OBJ, IID, HRESULT);
// USESUFFIX(AE_CHECK_COM, "ERROR %!HRESULT!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_OBJ_IID_HRESULT(LEVEL, OBJ, IID, HR)        WPP_EX_TRACELEVEL_HRESULT(LEVEL, HR)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_PRE(LEVEL, OBJ, IID, HR)       WPP_TRACELEVEL_HRESULT_PRE(LEVEL, HR)

// �������� ������� �����������
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(LEVEL, OBJ, IID, HR)   WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)

// ����������� ����������
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, FILE, LINE)                  \
    com_exception(OBJ, IID, WPP_VAR(LINE), FILE, LINE).trace();                     \
    throw gcnew System::ComponentModel::Win32Exception(WPP_VAR(LINE));  
#else
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, FILE, LINE)                  \
    com_exception(OBJ, IID, WPP_VAR(LINE), FILE, LINE).raise();
#endif 

// �������� ������� ������
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_POST(LEVEL, OBJ, IID, HR)                    \
    ; if (WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(LEVEL, OBJ, IID, HR)) {            \
         WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, __FILE__, __LINE__)         \
    }}

// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_LOGGER(LEVEL, OBJ, IID, HR)    WPP_TRACELEVEL_HRESULT_LOGGER(LEVEL, HR)
#else 
#define AE_CHECK_COM(OBJ, IID, HR)                                                                                                \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_OBJ_IID_HRESULT(TRACE_LEVEL_ERROR, OBJ, IID, HR), "ERROR %!HRESULT!", WPP_VAR(__LINE__))     \
    WPP_TRACELEVEL_OBJ_IID_HRESULT_PRE(TRACE_LEVEL_ERROR, OBJ, IID, HR)                                                           \
    (void)((                                                                                                                      \
        WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(TRACE_LEVEL_ERROR, OBJ, IID, HR)                                                   \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!HRESULT!", WPP_VAR(__LINE__))), 1 : 0                                                    \
    ))                                                                                                                            \
    WPP_TRACELEVEL_OBJ_IID_HRESULT_POST(TRACE_LEVEL_ERROR, OBJ, IID, HR)                                  
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ PKCS11
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(PKCS11, WPP_LOG_CPPNAME, const pkcs11_error&, ItemString, "s", pkcs11, 0);
// FUNC AE_CHECK_PKCS11{TRACELEVEL=TRACE_LEVEL_ERROR}(PKCS11);
// USESUFFIX(AE_CHECK_PKCS11, "ERROR %!PKCS11!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_PKCS11(LEVEL, CODE)       	(CK_ULONG, CODE, is_pkcs11_error, LEVEL)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_PKCS11_PRE(LEVEL, CODE)      

// �������� ������� �����������
#define WPP_TRACELEVEL_PKCS11_ENABLED(LEVEL, CODE)   	                    \
    is_pkcs11_error(WPP_VAR(__LINE__))

// ����������� ����������
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_PKCS11_RAISE(FILE, LINE)    	                        \
    pkcs11_exception(WPP_VAR(LINE), FILE, LINE).trace();                    \
    throw gcnew Aladdin::PKCS11::Exception(WPP_VAR(LINE));
#else 
#define WPP_TRACELEVEL_PKCS11_RAISE(FILE, LINE)           	                \
    pkcs11_exception(WPP_VAR(LINE), FILE, LINE).raise();    
#endif 

// �������� ������� ������
#define WPP_TRACELEVEL_PKCS11_POST(LEVEL, CODE)                             \
    ; if (WPP_TRACELEVEL_PKCS11_ENABLED(LEVEL, CODE)) {                     \
         WPP_TRACELEVEL_PKCS11_RAISE(__FILE__, __LINE__)                    \
    }}

// ����������� �����������
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
// ����������� ������ OpenSSL
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(OPENSSL, WPP_LOG_CPPNAME, const openssl_error&, ItemString, "s", openssl, 0);
// FUNC AE_CHECK_OPENSSL{TRACELEVEL=TRACE_LEVEL_ERROR}(OPENSSL);
// USESUFFIX(AE_CHECK_OPENSSL, "ERROR %!OPENSSL!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_OPENSSL(LEVEL, RET)       	(unsigned long, (RET) ? 0 : ERR_get_error(), is_openssl_error, LEVEL)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_OPENSSL_PRE(LEVEL, RET)      

// �������� ������� �����������
#define WPP_TRACELEVEL_OPENSSL_ENABLED(LEVEL, RET)   	                    \
    is_openssl_error(WPP_VAR(__LINE__))

// ����������� ����������
#define WPP_TRACELEVEL_OPENSSL_RAISE(FILE, LINE)                            \
    openssl_exception(WPP_VAR(LINE), FILE, LINE).raise();    

// �������� ������� ������
#define WPP_TRACELEVEL_OPENSSL_POST(LEVEL, RET)                             \
    ; if (WPP_TRACELEVEL_OPENSSL_ENABLED(LEVEL, RET)) {                     \
         WPP_TRACELEVEL_OPENSSL_RAISE(__FILE__, __LINE__)                   \
    }}

// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_OPENSSL_LOGGER(LEVEL, RET)   	WppGetLogger(),
#else 
#define AE_CHECK_OPENSSL(RET)                                                                     		        \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_OPENSSL(TRACE_LEVEL_ERROR, RET), "ERROR %!OPENSSL!", WPP_VAR(__LINE__))    \
    WPP_TRACELEVEL_OPENSSL_PRE(TRACE_LEVEL_ERROR, RET)                                            		        \
    (void)((                                                                                                    \
        WPP_TRACELEVEL_OPENSSL_ENABLED(TRACE_LEVEL_ERROR, RET)                                    		        \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!OPENSSL!", WPP_VAR(__LINE__))), 1 : 0                                  \
    ))                                                                                            		        \
    WPP_TRACELEVEL_OPENSSL_POST(TRACE_LEVEL_ERROR, RET)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ ODBC
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(ODBC, WPP_LOG_CPPNAME, const odbc_error&, ItemString, "s", odbc, 0);
// FUNC AE_CHECK_ODBC{TRACELEVEL=TRACE_LEVEL_ERROR}(CAT, HANDLE, TYPE, ODBC);
// USESUFFIX(AE_CHECK_ODBC, "ERROR %!ODBC!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_CAT_HANDLE_TYPE_ODBC(LEVEL, CAT, HANDLE, TYPE, ODBC)       	(odbc_error, odbc_error(CAT, ODBC), is_odbc_error, LEVEL)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_PRE(LEVEL, CAT, HANDLE, TYPE, ODBC)      

// �������� ������� �����������
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_ENABLED(LEVEL, CAT, HANDLE, TYPE, ODBC)   	        \
    is_odbc_error(WPP_VAR(__LINE__))

// ����������� ����������
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_RAISE(HANDLE, TYPE, FILE, LINE)    	                \
    odbc_exception(WPP_VAR(LINE), HANDLE, TYPE, FILE, LINE).raise();    

// �������� ������� ������
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_POST(LEVEL, CAT, HANDLE, TYPE, ODBC)                \
    ; if (WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_ENABLED(LEVEL, CAT, HANDLE, TYPE, ODBC)) {        \
         WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_RAISE(HANDLE, TYPE, __FILE__, __LINE__)            \
    }}

// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_LOGGER(LEVEL, CAT, HANDLE, TYPE, ODBC)   	WppGetLogger(),
#else 
#define AE_CHECK_ODBC(CAT, HANDLE, TYPE, ODBC)                                                               			            		\
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_CAT_HANDLE_TYPE_ODBC(TRACE_LEVEL_ERROR, CAT, HANDLE, TYPE, ODBC), "ERROR %!ODBC!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_PRE(TRACE_LEVEL_ERROR, CAT, HANDLE, TYPE, ODBC)                               	            		\
    (void)((                                                                                      							            	\
        WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_ENABLED(TRACE_LEVEL_ERROR, CAT, HANDLE, TYPE, ODBC)                       	            		\
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!ODBC!", WPP_VAR(__LINE__))), 1 : 0                                									\
    ))                                                                                      							            		\
    WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_POST(TRACE_LEVEL_ERROR, CAT, HANDLE, TYPE, ODBC)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ OCI
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(OCI, WPP_LOG_CPPNAME, const oci_error&, ItemString, "s", oci, 0);
// FUNC AE_CHECK_OCI{TRACELEVEL=TRACE_LEVEL_ERROR}(CAT, OCI, ERROR);
// USESUFFIX(AE_CHECK_OCI, "ERROR %!OCI!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_CAT_OCI_ERROR(LEVEL, CAT, OCI, ERROR)       	(oci_error, oci_error(CAT, OCI), is_oci_error, LEVEL)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_CAT_OCI_ERROR_PRE(LEVEL, CAT, OCI, ERROR)      

// �������� ������� �����������
#define WPP_TRACELEVEL_CAT_OCI_ERROR_ENABLED(LEVEL, CAT, OCI, ERROR)        \
    is_oci_error(WPP_VAR(__LINE__))

// ����������� ����������
#define WPP_TRACELEVEL_CAT_OCI_ERROR_RAISE(ERROR, FILE, LINE)    	        \
    oci_exception(WPP_VAR(LINE), ERROR, FILE, LINE).raise();

// �������� ������� ������
#define WPP_TRACELEVEL_CAT_OCI_ERROR_POST(LEVEL, CAT, OCI, ERROR)           \
    ; if (WPP_TRACELEVEL_CAT_OCI_ERROR_ENABLED(LEVEL, CAT, OCI, ERROR)) {   \
         WPP_TRACELEVEL_CAT_OCI_ERROR_RAISE(ERROR, __FILE__, __LINE__)  	\
    }}
// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_CAT_OCI_ERROR_LOGGER(LEVEL, CAT, OCI, ERROR)   	WppGetLogger(),
#else
#define AE_CHECK_OCI(CAT, OCI, ERROR)                                                                           			\
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_CAT_OCI_ERROR(TRACE_LEVEL_ERROR, CAT, OCI, ERROR), "ERROR %!OCI!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_CAT_OCI_ERROR_PRE(TRACE_LEVEL_ERROR, CAT, OCI, ERROR)                               	        			\
    (void)((                                                                                                          		\
        WPP_TRACELEVEL_CAT_OCI_ERROR_ENABLED(TRACE_LEVEL_ERROR, CAT, OCI, ERROR)                       	        			\
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!OCI!", WPP_VAR(__LINE__))), 1 : 0                                		            \
    ))                                                                                                          			\
    WPP_TRACELEVEL_CAT_OCI_ERROR_POST(TRACE_LEVEL_ERROR, CAT, OCI, ERROR)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ LIBPQ
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(LIBPQ, WPP_LOG_CPPNAME, const libpq_error&, ItemString, "s", libpq, 0);
// FUNC AE_CHECK_LIBPQ{TRACELEVEL=TRACE_LEVEL_ERROR}(LIBPQ);
// USESUFFIX(AE_CHECK_LIBPQ, "ERROR %!LIBPQ!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_LIBPQ(LEVEL, RESULT)        (PGresult*, RESULT, is_libpq_error, LEVEL)

// ���������� ���� ������
#define WPP_TRACELEVEL_LIBPQ_PRE(LEVEL, RESULT)       

// �������� ������� �����������
#define WPP_TRACELEVEL_LIBPQ_ENABLED(LEVEL, RESULT)                     \
    is_libpq_error(WPP_VAR(__LINE__))

// ����������� ����������
#define WPP_TRACELEVEL_LIBPQ_RAISE(FILE, LINE)                          \
    libpq_exception(WPP_VAR(LINE), FILE, LINE).raise();

// �������� ������� ������
#define WPP_TRACELEVEL_LIBPQ_POST(LEVEL, RESULT)                        \
    ; if (WPP_TRACELEVEL_LIBPQ_ENABLED(LEVEL, RESULT)) {                \
         WPP_TRACELEVEL_LIBPQ_RAISE(__FILE__, __LINE__)                 \
    }}
// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_LIBPQ_LOGGER(LEVEL, RESULT)    WppGetLogger(),
#else 
#define AE_CHECK_LIBPQ(RESULT)                                                                          	    \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_LIBPQ(TRACE_LEVEL_ERROR, RESULT), "ERROR %!LIBPQ!", WPP_VAR(__LINE__))     \
    WPP_TRACELEVEL_LIBPQ_PRE(TRACE_LEVEL_ERROR, RESULT)                                               		    \
    (void)((                                                                                                  	\
        WPP_TRACELEVEL_LIBPQ_ENABLED(TRACE_LEVEL_ERROR, RESULT)                                         	    \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!LIBPQ!", WPP_VAR(__LINE__))), 1 : 0                                    \
    ))                                                                                                  	    \
    WPP_TRACELEVEL_LIBPQ_POST(TRACE_LEVEL_ERROR, RESULT)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ Python
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(PYTHON, WPP_LOG_CPPNAME, const python_error&, ItemString, "s", python, 0);
// FUNC AE_CHECK_PYTHON{TRACELEVEL=TRACE_LEVEL_ERROR}(PYTHON);
// USESUFFIX(AE_CHECK_PYTHON, "ERROR %!PYTHON!", WPP_VAR(__LINE__));
// end_wpp

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_PYTHON(LEVEL, CAT)       	    (python_error, CAT, is_python_error, LEVEL)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_PYTHON_PRE(LEVEL, CAT)      

// �������� ������� �����������
#define WPP_TRACELEVEL_PYTHON_ENABLED(LEVEL, CAT)   	                \
    is_python_error(WPP_VAR(__LINE__))

// ����������� ����������
#define WPP_TRACELEVEL_PYTHON_RAISE(FILE, LINE)    	                    \
    python_exception(WPP_VAR(LINE), FILE, LINE).raise();    

// �������� ������� ������
#define WPP_TRACELEVEL_PYTHON_POST(LEVEL, CAT)                          \
    ; if (WPP_TRACELEVEL_PYTHON_ENABLED(LEVEL, CAT)) {                  \
         WPP_TRACELEVEL_PYTHON_RAISE(__FILE__, __LINE__)	            \
    }}
// ����������� �����������
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_PYTHON_LOGGER(LEVEL, CAT)   	WppGetLogger(),
#else 
#define AE_CHECK_PYTHON(CAT)                                                               			            \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_PYTHON(TRACE_LEVEL_ERROR, CAT), "ERROR %!PYTHON!", WPP_VAR(__LINE__))  	\
    WPP_TRACELEVEL_PYTHON_PRE(TRACE_LEVEL_ERROR, CAT)                               	            			\
    (void)((                                                                                      			    \
        WPP_TRACELEVEL_PYTHON_ENABLED(TRACE_LEVEL_ERROR, CAT)                       	            			\
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!PYTHON!", WPP_VAR(__LINE__))), 1 : 0                                	\
    ))                                                                                      					\
    WPP_TRACELEVEL_PYTHON_POST(TRACE_LEVEL_ERROR, CAT)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (77921413, 5345, 4626, B028, C3AFB9DCBF05)
#if defined _NTDDK_
#include "TraceDriver.h"
#else 
#include "TraceUser.h"
#endif 
#else 
#if defined _NTDDK_
#define WPP_INIT_TRACING(pDriver, pRegPath) UNREFERENCED_PARAMETER(pRegPath)
#define WPP_CLEANUP(     pDriver)           UNREFERENCED_PARAMETER(pDriver) 
#else 
#define WPP_INIT_TRACING(Application)       ((void)0)
#define WPP_CLEANUP(                )       ((void)0)
#endif 
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����� �������� ���������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
inline PWPP_TRACE_CONTROL_BLOCK WppGetControl(TRACEHANDLE hRegistrationHandle)
{
    // ��������� ������� �����������
    if (WPP_CB == (WPP_CB_TYPE*)&WPP_CB) return nullptr; 

    // ������� �� ���� ������� ����������
    PWPP_TRACE_CONTROL_BLOCK pControl = &WPP_CB[0].Control;

    // ��� ���� ������������������ �����������
    for(; pControl; pControl = pControl->Next) 
    {
        // ��������� ������� ��������������
        if (!pControl->ControlGuid) continue; 
#if defined _NTDDK_
        // ��������� ���������� ��������������
        if (pControl->RegHandle == hRegistrationHandle) return pControl;
#else 
        // ��������� ���������� ��������������
        if (pControl->UmRegistrationHandle == hRegistrationHandle) return pControl;
#endif 
    }
    return nullptr; 
}

inline PWPP_TRACE_CONTROL_BLOCK WppGetControl(const GUID& componentGUID)
{
    // ��������� ������� �����������
    if (WPP_CB == (WPP_CB_TYPE*)&WPP_CB) return nullptr; 

    // ������� �� ���� ������� ����������
    PWPP_TRACE_CONTROL_BLOCK pControl = &WPP_CB[0].Control;

    // ��� ���� ������������������ �����������
    for(; pControl; pControl = pControl->Next) 
    {
        // ��������� ������� ��������������
        if (!pControl->ControlGuid) continue; 

        // ��������� ���������� ��������������
        if (IsEqualGUID(*pControl->ControlGuid, componentGUID)) return pControl;
    }
    return nullptr; 
}

inline PWPP_TRACE_CONTROL_BLOCK WppGetControl()
{
    // ������� ������������� ����������
    GUID componentGUID = WPP_XGLUE4(WPP_, ThisDir, _CTLGUID_, WPP_EVAL(WPP_CONTROL_NAME)); 

    // ����� ���� ����������
    return WppGetControl(componentGUID); 
}

inline TRACEHANDLE WppGetLogger()
{
    // ����� ���� ����������
    PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(); 

#if !defined _NTDDK_
    // ��� ������������ ������
    if (pControl && pControl->Options == WPP_VER_WIN2K_CB_FORWARD_PTR)
    {
        // ������� ��������� ������
        if (pControl->Win2kCb) return pControl->Win2kCb->Logger; 
    }
    // ��� ������������ ������
    if (pControl && pControl->Options == WPP_VER_WHISTLER_CB_FORWARD_PTR)
    {
        // ��������������� ���� ����������
        if (pControl->Cb) pControl = pControl->Cb; 
    }
#endif 
    // ������� ��������� ������
    return (pControl) ? pControl->Logger : 0; 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������������� �����������
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline ULONG WppRegisterTraceGuids(
    WMIDPREQUEST RequestAddress, PVOID RequestContext, 
    LPCGUID ControlGuid, ULONG GuidCount, PTRACE_GUID_REGISTRATION TraceGuidReg, 
    LPCWSTR MofImagePath, LPCWSTR MofResourceName, PTRACEHANDLE phRegistrationHandle)
{
    // ������� ������� �������
    ULONG ret = ::RegisterTraceGuidsW(RequestAddress, RequestContext, 
        ControlGuid, GuidCount, TraceGuidReg, 
        MofImagePath, MofResourceName, phRegistrationHandle
    ); 
    // ��������� ���������� ������
    if (ret != ERROR_SUCCESS) return ret; 

    // ����� �������� ���� ����������
    PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(*phRegistrationHandle); 

    // ��������� ������������ ��������
    if (!pControl || pControl->Options != 0) return ret; 

    // �������� ������ ��� ��������������� ����� ����������
    if (PWPP_TRACE_CONTROL_BLOCK pCB = new WPP_TRACE_CONTROL_BLOCK)
    {
        // ��������� �������������
        pCB->Options = 0; pCB->Logger = pControl->Logger; 

        // ������� ������������ ���������������
        pControl->Options = WPP_VER_WHISTLER_CB_FORWARD_PTR; pControl->Cb = pCB; 

        // ������� ������ ��������� ����� ����������
        pCB->UmRegistrationHandle = pControl->UmRegistrationHandle; 

        // ������� ������ ��������� ����� ����������
        pCB->ControlGuid = ControlGuid; pCB->Level = pControl->Level; 
        
        // ������� ������ ��������� ����� ����������
        pCB->FlagsLen = pControl->FlagsLen; pCB->Flags[0] = pControl->Flags[0]; 

        // ��������� ��������� �����������
        trace::ControlParameters* pControlParameters = new(std::nothrow) trace::ControlParameters(); 

        // ��������� �������� ���������� �����������
        pCB->Next = (PWPP_TRACE_CONTROL_BLOCK)pControlParameters; 
    }
    return ret; 
}

inline ULONG WppUnregisterTraceGuids(TRACEHANDLE hRegistrationHandle)
{
    // ����� �������� ���� ����������
    PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(hRegistrationHandle); 

    // ��������� ������������ ��������
    if (pControl && pControl->Options == WPP_VER_WHISTLER_CB_FORWARD_PTR) 
    {
        // �������� ����� ��������������� �����
        if (PWPP_TRACE_CONTROL_BLOCK pCB = pControl->Cb)
        {        
            // ������������ �������� ������
            pControl->Options = 0; pControl->Logger = pCB->Logger; 

            // ������������ �������� ������
            pControl->UmRegistrationHandle = pCB->UmRegistrationHandle; 
            
            // ������������ �������� ������
            pControl->ControlGuid = pCB->ControlGuid; pControl->Level = pCB->Level; 

            // ������������ �������� ������
            pControl->FlagsLen = pCB->FlagsLen; pControl->Flags[0] = pCB->Flags[0];

            // ���������� ���������� ������
            if (pCB->Next) delete (trace::ControlParameters*)(pCB->Next); delete pCB; 
        }
    }
    // ������� ������� �������
    return ::UnregisterTraceGuids(hRegistrationHandle); 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined _NTDDK_
inline void WppNotificationCallback(LPCGUID, TRACEHANDLE, BOOLEAN, ULONG, UCHAR) {}
#else 
inline void WppNotificationCallback(LPCGUID ControlGuid, 
    TRACEHANDLE hLogger, BOOLEAN enable, ULONG flags, UCHAR level) 
{
    // ����� �������� ���� ����������
    if (!enable) return; PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(*ControlGuid); 

    // ��������� ������������ ��������
    if (!pControl || pControl->Options != WPP_VER_WHISTLER_CB_FORWARD_PTR) return; 

    // �������� ����� ��������������� �����
    if (PWPP_TRACE_CONTROL_BLOCK pCB = pControl->Cb)
    {
        // ��������� �������� ������
        pCB->Logger = hLogger; pCB->Level = level; pCB->Flags[0] = flags; 

        // �������� ��������� �����������
        ((trace::ControlParameters*)(pCB->Next))->Update(); 
    }
}
namespace trace {
inline const ControlParameters* GetControlParameters() 
{
    // ����� ���� ����������
    PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(); if (!pControl) return nullptr; 
    
    // ��������� ������� �����
    if (pControl->Options != WPP_VER_WHISTLER_CB_FORWARD_PTR || !pControl->Cb) return nullptr; 

    // ��������� �������������� ����
    return (const ControlParameters*)(pControl->Cb->Next); 
}
}
#endif
#endif

///////////////////////////////////////////////////////////////////////////////
// ����������� �����/������ �� �������. ������� ������ �� ������ ���� 
// ������������� (inline) �� ��������� ��������� �������: 
// 1) ��c����������� �������������� ������������ � ����������� ������ 
// ��������� �������� ���������� �, �������������, ��������������� ��� ������ 
// ����������� (��������� �������� __FILE__ � �������������� ������� �����
// ��������� ������); 
// 2) ��������� � .TMF-���� ��� �������������� ��������� Trace.h �������� 
// ���������, ������������� ������ �������� ���������� (�������� ����������, 
// � ������� ������������ ������ ������������ � �����������). 
///////////////////////////////////////////////////////////////////////////////
namespace trace { 
class scope { private: const char* szFunction; 

    // �����������
    public: WPP_NOINLINE scope(const char* szFunc) : szFunction(szFunc)
    {
        // ��������� ����������� �����
        ATRACE(TRACE_LEVEL_VERBOSE, "--> %hs", szFunction);
    }
    // ����������
    public: WPP_NOINLINE ~scope()
    {
        // ��������� ����������� ������
        ATRACE(TRACE_LEVEL_VERBOSE, "<-- %hs", szFunction);
    }
};    
}
// ����������� ����������� �����
#define $ trace::scope WPP_VAR(__LINE__)(__FUNC__);

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ �������������� �������
///////////////////////////////////////////////////////////////////////////////
WPP_NOINLINE inline void WppTraceStringA(int level, const char* sz, size_t cch) 
{ 
    // ���������� ������ ������
    if (!sz) { return; } if (cch == (size_t)(-1)) { cch = strlen(sz); } switch (level)
    {
    // ������� ������
    case TRACE_LEVEL_NONE       : ATRACE(TRACE_LEVEL_NONE       , "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_CRITICAL   : ATRACE(TRACE_LEVEL_CRITICAL   , "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_ERROR      : ATRACE(TRACE_LEVEL_ERROR      , "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_WARNING    : ATRACE(TRACE_LEVEL_WARNING    , "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_INFORMATION: ATRACE(TRACE_LEVEL_INFORMATION, "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_VERBOSE    : ATRACE(TRACE_LEVEL_VERBOSE    , "%!.*hs!", trace::_str(sz, cch)); break;
    }
}

WPP_NOINLINE inline void WppTraceStringW(int level, const wchar_t* sz, size_t cch) 
{ 
    // ���������� ������ ������
    if (!sz) { return; } if (cch == (size_t)(-1)) { cch = wcslen(sz); } switch (level)
    {
    // ������� ������
    case TRACE_LEVEL_NONE       : ATRACE(TRACE_LEVEL_NONE       , "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_CRITICAL   : ATRACE(TRACE_LEVEL_CRITICAL   , "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_ERROR      : ATRACE(TRACE_LEVEL_ERROR      , "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_WARNING    : ATRACE(TRACE_LEVEL_WARNING    , "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_INFORMATION: ATRACE(TRACE_LEVEL_INFORMATION, "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_VERBOSE    : ATRACE(TRACE_LEVEL_VERBOSE    , "%!.*ls!", trace::_wstr(sz, cch)); break;
    }
}
inline void ATRACESTR(int level, const char   * sz, size_t cch = -1) { WppTraceStringA(level, sz, cch); }
inline void ATRACESTR(int level, const wchar_t* sz, size_t cch = -1) { WppTraceStringW(level, sz, cch); }

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������� ����������� ������
///////////////////////////////////////////////////////////////////////////////
inline void ATRACEDUMP(int level, const void* pvBlock, size_t cbBlock)
{
    static const char DIGITS[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    // ��������� �������������� ����
    const unsigned char* pbBlock = (const unsigned char*)pvBlock; 

    // ������� ����� ���������� �������
    char buffer[2 * sizeof(void*) + 2 + 64 + 1] = {0}; 

    // ���������� ����� ��� �������������� ��������
    char* szValue = buffer + 2 * sizeof(void*) + 2; 

    // ��� ���� �����
    for (size_t i = 0; i < (cbBlock + 15) / 16; i++)
    {
        // ��������� ������� �����
        const unsigned char* ptr = pbBlock + i * 16; memset(szValue, ' ', 64);

        // ��������������� �����
        trace::snprintf_ptr(buffer, 2 * sizeof(void*) + 1, ptr); 

        // ������� ����������� ������ � ��������
        buffer[2 * sizeof(void*) + 0] = ':'; buffer[2 * sizeof(void*) + 1] = ' '; 

        // ��� ���� ������ ������
        for (size_t j = 0; (j < 16) && (i * 16 + j < cbBlock); j++)
        {
            // ������� ��������� ����
            unsigned char ch = ptr[j];

            // ������� ����������������� �������������
            szValue[j * 3 + 0] = DIGITS[ch / 16];
            szValue[j * 3 + 1] = DIGITS[ch % 16];

            // ������� ���������� �������������
            szValue[48 + j] = (' ' <= ch && ch <= 127) ? ch : '.';
        }
        // ��������� �����������
        ATRACESTR(level, buffer);
    }                                                                   
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������� ����������� ������
///////////////////////////////////////////////////////////////////////////////
inline void ATRACE_MULTILINE(int level, const char* szMessage)
{
    // ��� ���� ��������
    while (szMessage && *szMessage)
    {
        // ����� ���������� ���������
        if (const char* szLast = strchr(szMessage, '\n')) 
        { 
            // ������� ������� ��������� ������
            const char* szEnd = szLast; if (szLast != szMessage)
            {
                // ������� ������� ��������� ������
                if (*(szLast - 1) == '\r') szEnd--; 
            }
            // ������� ���������
            ATRACESTR(level, szMessage, szEnd - szMessage);

            // ���������� ���������
            szMessage = szLast + 1; continue; 
        }
        // ������� ���������� ������
        ATRACESTR(level, szMessage); break; 
    }
}
inline void ATRACE_MULTILINE(int level, const wchar_t* szMessage)
{
    // ��� ���� ��������
    while (szMessage && *szMessage)
    {
        // ����� ���������� ���������
        if (const wchar_t* szLast = wcschr(szMessage, L'\n')) 
        { 
            // ������� ������� ��������� ������
            const wchar_t* szEnd = szLast; if (szLast != szMessage)
            {
                // ������� ������� ��������� ������
                if (*(szLast - 1) == L'\r') szEnd--; 
            }
            // ������� ���������
            ATRACESTR(level, szMessage, szEnd - szMessage);

            // ���������� ���������
            szMessage = szLast + 1; continue; 
        }
        // ������� ���������� ������
        ATRACESTR(level, szMessage); break; 
    }
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
#include "TraceError.h"     // ����������� ������
#include "TracePosix.h"     // ����������� ������ POSIX

#if defined _WIN32
#include "TraceWindows.h"   // ����������� ������ Windows
#include "TraceCOM.h"       // ����������� ������ COM
#endif 
#endif 
