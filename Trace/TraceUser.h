// 8144776b194fd0c696946c05805efa1e Generated file. Do not edit.
// File created by WPP compiler version 10.0.19041
// from template um-default.tpl

#pragma once

// template um-header.tpl

#ifdef  WPP_THIS_FILE
// included twice
#       define  WPP_ALREADY_INCLUDED
#       undef   WPP_THIS_FILE
#endif  // #ifdef WPP_THIS_FILE

#define WPP_THIS_FILE Trace_h

#ifndef WPP_ALREADY_INCLUDED


#ifdef BUILD_MINWIN
#include <windowscore.h>
#else
#include <windows.h>
#endif

#include <wmistr.h>
#include <evntrace.h>
#ifndef WPP_TRACE_W2K_COMPATABILITY
#include <sddl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// LEGACY: This structure was used by Win2k RpcRt4 and cluster tracing

typedef struct _WPP_WIN2K_CONTROL_BLOCK {
    TRACEHANDLE Logger;
    ULONG Flags;
    ULONG Level;
    LPCGUID ControlGuid;
} WPP_WIN2K_CONTROL_BLOCK, *PWPP_WIN2K_CONTROL_BLOCK;

#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used nameless struct/union

typedef struct _WPP_TRACE_CONTROL_BLOCK
{
    struct _WPP_TRACE_CONTROL_BLOCK *Next;
    TRACEHANDLE     UmRegistrationHandle;
    union {
        TRACEHANDLE              Logger;
        PWPP_WIN2K_CONTROL_BLOCK Win2kCb;
        PVOID                    Ptr;
        struct _WPP_TRACE_CONTROL_BLOCK *Cb;
    };

    UCHAR           FlagsLen;
    UCHAR           Level;
    USHORT          Options;
    ULONG           Flags[1];
    LPCGUID         ControlGuid;
#if ENABLE_WPP_RECORDER
    PVOID           AutoLogContext;
    USHORT          AutoLogVerboseEnabled;
    USHORT          AutoLogAttachToMiniDump;
#endif
} WPP_TRACE_CONTROL_BLOCK, *PWPP_TRACE_CONTROL_BLOCK;
#pragma warning(pop)

#ifdef WPP_USE_NTDLL_FUNCTIONS
// Not supported.
#include <wpp_use_ntdll_functions.h>
#endif

#define WPP_IsValidSid IsValidSid
#define WPP_GetLengthSid GetLengthSid

#ifndef WPP_TRACE
#define WPP_TRACE TraceMessage
#endif

#ifndef WPP_UNREGISTER_TRACE_GUIDS
#define WPP_UNREGISTER_TRACE_GUIDS  UnregisterTraceGuids
#endif


#ifndef WPP_REGISTER_TRACE_GUIDS
#define WPP_REGISTER_TRACE_GUIDS  RegisterTraceGuids
#endif


#ifndef WPP_GET_TRACE_LOGGER_HANDLE
#define WPP_GET_TRACE_LOGGER_HANDLE  GetTraceLoggerHandle
#endif

#ifndef WPP_GET_TRACE_ENABLE_LEVEL
#define WPP_GET_TRACE_ENABLE_LEVEL  GetTraceEnableLevel
#endif

#ifndef WPP_GET_TRACE_ENABLE_FLAGS
#define WPP_GET_TRACE_ENABLE_FLAGS  GetTraceEnableFlags
#endif

enum {
    WPP_VER_WIN2K_CB_FORWARD_PTR    = 0x01,
    WPP_VER_WHISTLER_CB_FORWARD_PTR = 0x02,
    WPP_VER_LH_CB_FORWARD_PTR = 0x03
};

#if ENABLE_WPP_RECORDER

#ifndef WPP_RECORDER
#define WPP_RECORDER WppAutoLogTrace
#endif

//
// This setting is only applicable when IFR is enabled.
// Setting this to 1 will allow a WPP trace session to 
// capture trace messages as usual i.e it will require the
// user to provide WPP trace ENABLED and LOGGER macro. If 
// this is set to 0 by default the IFR trace filter also
// affects which trace messages land in the WPP trace session.
//
#if !defined(ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER)
#define ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER 0
#endif

#if !defined(WPP_RECORDER_LEVEL_FLAGS_ARGS)
#define WPP_RECORDER_LEVEL_FLAGS_ARGS(lvl, flags) WPP_CONTROL(WPP_BIT_ ## flags).AutoLogContext, lvl, WPP_BIT_ ## flags
#define WPP_RECORDER_LEVEL_FLAGS_FILTER(lvl,flags) (lvl < TRACE_LEVEL_VERBOSE || WPP_CONTROL(WPP_BIT_ ## flags).AutoLogVerboseEnabled)
#endif

#if !defined(WPP_RECORDER_FLAGS_LEVEL_ARGS)
#define WPP_RECORDER_FLAGS_LEVEL_ARGS(flags, lvl) WPP_RECORDER_LEVEL_FLAGS_ARGS(lvl, flags)
#define WPP_RECORDER_FLAGS_LEVEL_FILTER(flags, lvl) WPP_RECORDER_LEVEL_FLAGS_FILTER(lvl, flags)
#endif

#if !defined(WPP_RECORDER_LEVEL_ARGS)
#define WPP_RECORDER_LEVEL_ARGS(lvl) WPP_CONTROL(WPP_BIT_ ## lvl).AutoLogContext, 0, WPP_BIT_ ## lvl
#define WPP_RECORDER_LEVEL_FILTER(lvl) (WPP_CONTROL(WPP_BIT_ ## lvl).AutoLogVerboseEnabled)
#endif

NTSTATUS
WppAutoLogTrace(
    _In_ PVOID              AutoLogContext,
    _In_ UCHAR              MessageLevel,
    _In_ ULONG              MessageFlags,
    _In_ LPGUID             MessageGuid,
    _In_ USHORT             MessageNumber,
    _In_ ...
    );

#endif // ENABLE_WPP_RECORDER

//
// WPP_INIT_TRACING and WPP_CLEANUP macros are defined differently for kernel
// mode and user mode. In order to support mode-agnostic WDF drivers,
// WPP_INIT_TRACING and WPP_CLEANUP macros for UMDF 2.x user-mode drivers are
// being updated to be same as kernel mode macros. This difference is based
// upon the macro WPP_MACRO_USE_KM_VERSION_FOR_UM.
//

#ifdef WPP_MACRO_USE_KM_VERSION_FOR_UM

VOID WppCleanupUm( VOID );
#define WPP_CLEANUP(DrvObj) WppCleanupUm()
#else
VOID WppCleanupUm( VOID );
#define WPP_CLEANUP() WppCleanupUm()
#endif

#define WppLoadTracingSupport

//
// For getting private callback, implement a function with the signature below.
// To register the function: #define WPP_PRIVATE_ENABLE_CALLBACK MyPrivateCallback
// If multiple control guids are used, be sure to compare Guid to the one of interest.
//

#if defined(WPP_PRIVATE_ENABLE_CALLBACK)

typedef
VOID
(NTAPI *PFN_WPP_PRIVATE_ENABLE_CALLBACK)(
    _In_ LPCGUID Guid,
    _In_ TRACEHANDLE Logger,
    _In_ BOOLEAN Enable,
    _In_ ULONG Flags,
    _In_ UCHAR Level
    );

#endif

//
// For generating CAPTURE_STATE callback (Win7+), implement a function with the signature
// below. To register the function: #define WPP_CAPTURE_STATE_CALLBACK MyCaptureStateCallback
// If multiple control guids are used, be sure to compare Guid to the one of interest.
//

#if defined(WPP_CAPTURE_STATE_CALLBACK)

typedef
VOID
(NTAPI *PFN_WPP_CAPTURE_STATE_CALLBACK)(
    _In_ LPCGUID Guid,
    _In_ TRACEHANDLE Logger,
    _In_ ULONG Flags,
    _In_ UCHAR Level
    );

#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // #ifndef WPP_ALREADY_INCLUDED

// template control.tpl

//
//     Defines a set of macro that expand control model specified
//     with WPP_CONTROL_GUIDS (example shown below)
//     into an enum of trace levels and required structures that
//     contain the mask of levels, logger handle and some information
//     required for registration.
//

#ifndef WPP_ALREADY_INCLUDED

#define WPP_EVAL(x) x
#define WPP_STR(x)  #x
#define WPP_STRINGIZE(x) WPP_STR(x)
#define WPP_GLUE(a, b)  a ## b
#define WPP_GLUE3(a, b, c)  a ## b ## c
#define WPP_GLUE4(a, b, c, d)  a ## b ## c ## d
#define WPP_XGLUE(a, b) WPP_GLUE(a, b)
#define WPP_XGLUE3(a, b, c) WPP_GLUE3(a, b, c)
#define WPP_XGLUE4(a, b, c, d) WPP_GLUE4(a, b, c, d)

///////////////////////////////////////////////////////////////////////////////////
//
// #define WPP_CONTROL_GUIDS \
//     WPP_DEFINE_CONTROL_GUID(Regular,(81b20fea,73a8,4b62,95bc,354477c97a6f), \
//       WPP_DEFINE_BIT(Error)      \
//       WPP_DEFINE_BIT(Unusual)    \
//       WPP_DEFINE_BIT(Noise)      \
//    )        \
//    WPP_DEFINE_CONTROL_GUID(HiFreq,(91b20fea,73a8,4b62,95bc,354477c97a6f), \
//       WPP_DEFINE_BIT(Entry)      \
//       WPP_DEFINE_BIT(Exit)       \
//       WPP_DEFINE_BIT(ApiCalls)   \
//       WPP_DEFINE_BIT(RandomJunk) \
//       WPP_DEFINE_BIT(LovePoem)   \
//    )

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WPP_NO_CONTROL_GUIDS

#ifdef WPP_DEFAULT_CONTROL_GUID
#  ifdef WPP_CONTROL_GUIDS
#     error WPP_DEFAULT_CONTROL_GUID cannot be used together with WPP_CONTROL_GUIDS.
#  else // WPP_CONTROL_GUIDS
#     define WPP_CONTROL_GUIDS \
         WPP_DEFINE_CONTROL_GUID(Default,(WPP_DEFAULT_CONTROL_GUID), \
         WPP_DEFINE_BIT(Error)   \
         WPP_DEFINE_BIT(Unusual) \
         WPP_DEFINE_BIT(Noise)   \
      )
#  endif // WPP_CONTROL_GUIDS
#endif // WPP_DEFAULT_CONTROL_GUID

#ifndef WPP_CONTROL_GUIDS
#  pragma message(__FILE__ " : error : Please define control model via WPP_CONTROL_GUIDS or WPP_DEFAULT_CONTROL_GUID macros")
#  pragma message(__FILE__ " : error : don't forget to call WPP_INIT_TRACING and WPP_CLEANUP in your main, DriverEntry or DllInit")
#  pragma message(__FILE__ " : error : see tracewpp.doc for further information")
#  error WPP_CONTROL_GUIDS not defined.
#endif // WPP_CONTROL_GUIDS
// a set of macro to convert a guid in a form x(81b20fea,73a8,4b62,95bc,354477c97a6f)
// into either a a struct or text string

#define _WPPW(x) WPP_GLUE(L, x)

#define WPP_GUID_NORM(l,w1,w2,w3,ll) l ## w1 ## w2 ## w3 ## ll
#define WPP_GUID_TEXT(l,w1,w2,w3,ll) #l "-" #w1 "-" #w2 "-" #w3 "-" #ll
#define WPP_GUID_WTEXT(l,w1,w2,w3,ll) _WPPW(#l) L"-" _WPPW(#w1) L"-" _WPPW(#w2) L"-" _WPPW(#w3) L"-" _WPPW(#ll)
#define WPP_EXTRACT_BYTE(val,n) (((ULONGLONG)(0x ## val) >> (8 * n)) & 0xFF)
#define WPP_GUID_STRUCT(l,w1,w2,w3,ll) {0x ## l, 0x ## w1, 0x ## w2,\
     {WPP_EXTRACT_BYTE(w3, 1), WPP_EXTRACT_BYTE(w3, 0),\
      WPP_EXTRACT_BYTE(ll, 5), WPP_EXTRACT_BYTE(ll, 4),\
      WPP_EXTRACT_BYTE(ll, 3), WPP_EXTRACT_BYTE(ll, 2),\
      WPP_EXTRACT_BYTE(ll, 1), WPP_EXTRACT_BYTE(ll, 0)} }

#ifndef WPP_FORCEINLINE
#define WPP_FORCEINLINE __forceinline
#endif

// define an enum of control block names
//////
#define WPP_DEFINE_CONTROL_GUID(Name,Guid,Bits) WPP_XGLUE(WPP_CTL_, WPP_EVAL(Name)),
enum WPP_CTL_NAMES { WPP_CONTROL_GUIDS WPP_LAST_CTL};
#undef WPP_DEFINE_CONTROL_GUID

// define control guids
//////
#define WPP_DEFINE_CONTROL_GUID(Name,Guid,Bits) \
extern __declspec(selectany) const GUID WPP_XGLUE4(WPP_, ThisDir, _CTLGUID_, WPP_EVAL(Name)) = WPP_GUID_STRUCT Guid;
WPP_CONTROL_GUIDS
#undef WPP_DEFINE_CONTROL_GUID

// define enums of individual bits
/////
#define WPP_DEFINE_CONTROL_GUID(Name,Guid,Bits) \
    WPP_XGLUE(WPP_BLOCK_START_, WPP_EVAL(Name)) = WPP_XGLUE(WPP_CTL_, WPP_EVAL(Name)) * 0x10000, Bits WPP_XGLUE(WPP_BLOCK_END_, WPP_EVAL(Name)),
# define WPP_DEFINE_BIT(Name) WPP_BIT_ ## Name,
enum WPP_DEFINE_BIT_NAMES { WPP_CONTROL_GUIDS };
# undef WPP_DEFINE_BIT
#undef WPP_DEFINE_CONTROL_GUID

#define WPP_MASK(CTL)    (1 << ( ((CTL)-1) & 31 ))
#define WPP_FLAG_NO(CTL) ( (0xFFFF & ((CTL)-1) ) / 32)
#define WPP_CTRL_NO(CTL) ((CTL) >> 16)

// calculate how many DWORDs we need to get the required number of bits
// upper estimate. Sometimes will be off by one
#define WPP_DEFINE_CONTROL_GUID(Name,Guid,Bits) | WPP_XGLUE(WPP_BLOCK_END_, WPP_EVAL(Name))
enum _WPP_FLAG_LEN_ENUM { WPP_FLAG_LEN = 1 | ((0 WPP_CONTROL_GUIDS) & 0xFFFF) / 32 };
#undef WPP_DEFINE_CONTROL_GUID

//
// Check that maximum number of flags does not exceed 32
//
#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]
#endif

#define MAX_NUMBER_OF_ETW_FLAGS 34 // 32 flags plus 2 separators
#define WPP_DEFINE_CONTROL_GUID(Name,Guid,Bits) && ((WPP_XGLUE(WPP_BLOCK_END_, WPP_EVAL(Name) & 0xFFFF)) < MAX_NUMBER_OF_ETW_FLAGS)
enum _WPP_FLAG_LEN_ENUM_MAX { WPP_MAX_FLAG_LEN_CHECK = (1 WPP_CONTROL_GUIDS) };
#undef WPP_DEFINE_CONTROL_GUID

#ifndef WPP_CB
#define WPP_CB      WPP_GLOBAL_Control
#endif
#ifndef WPP_CB_TYPE
#define WPP_CB_TYPE WPP_PROJECT_CONTROL_BLOCK
#endif

#ifndef WPP_CHECK_INIT
#define WPP_CHECK_INIT (WPP_CB != (WPP_CB_TYPE*)&WPP_CB) &&
#endif

typedef union {
    WPP_TRACE_CONTROL_BLOCK Control;
    UCHAR ReserveSpace[ sizeof(WPP_TRACE_CONTROL_BLOCK) + sizeof(ULONG) * (WPP_FLAG_LEN - 1) ];
} WPP_CB_TYPE ;


extern __declspec(selectany) WPP_CB_TYPE *WPP_CB = (WPP_CB_TYPE*)&WPP_CB;

#if ENABLE_WPP_RECORDER
#ifndef WPP_RECORDER_CHECK_INIT
#define WPP_RECORDER_CHECK_INIT (WPP_RECORDER_INITIALIZED != (WPP_CB_TYPE*)&WPP_RECORDER_INITIALIZED) &&
#endif
// Global varaible used to track if WPP_RECORDER was initialized.
// It will be initialized on calling WPP_INIT_TRACING macro.
extern __declspec(selectany) WPP_CB_TYPE *WPP_RECORDER_INITIALIZED = (WPP_CB_TYPE*)&WPP_RECORDER_INITIALIZED;
#endif

#define WPP_CONTROL(CTL) (WPP_CB[WPP_CTRL_NO(CTL)].Control)

// Define the default WPP_LEVEL_LOGGER/WPP_LEVEL_ENABLED macros for the
// predefined DoTraceMessage(LEVEL) function.
#ifdef WPP_USE_TRACE_LEVELS

#ifndef WPP_LEVEL_LOGGER
#define WPP_LEVEL_LOGGER(lvl) (WPP_CONTROL(WPP_BIT_ ## DUMMY).Logger),
#endif
#ifndef WPP_LEVEL_ENABLED
#define WPP_LEVEL_ENABLED(lvl) (WPP_CONTROL(WPP_BIT_ ## DUMMY).Level >= lvl)
#endif

#else // WPP_USE_TRACE_LEVELS

// For historical reasons, the use of LEVEL means flags by default.
// This was a bad choice but very difficult to undo.
#ifndef WPP_LEVEL_LOGGER
#  define WPP_LEVEL_LOGGER(CTL)  (WPP_CONTROL(WPP_BIT_ ## CTL).Logger),
#endif
#ifndef WPP_LEVEL_ENABLED
#  define WPP_LEVEL_ENABLED(CTL) (WPP_CONTROL(WPP_BIT_ ## CTL).Flags[WPP_FLAG_NO(WPP_BIT_ ## CTL)] & WPP_MASK(WPP_BIT_ ## CTL))
#endif

#endif // WPP_USE_TRACE_LEVELS

// Define default WPP_FLAG_LOGGER/WPP_FLAG_ENABLED macros for convenience in
// defining a function that takes a FLAG parameter e.g. DoTrace(FLAG).
#ifndef WPP_FLAG_LOGGER
#  define WPP_FLAG_LOGGER(CTL)  (WPP_CONTROL(WPP_BIT_ ## CTL).Logger),
#endif
#ifndef WPP_FLAG_ENABLED
#  define WPP_FLAG_ENABLED(CTL) (WPP_CONTROL(WPP_BIT_ ## CTL).Flags[WPP_FLAG_NO(WPP_BIT_ ## CTL)] & WPP_MASK(WPP_BIT_ ## CTL))
#endif

#ifndef WPP_ENABLED
#  define WPP_ENABLED() 1
#endif
#ifndef WPP_LOGGER
#  define WPP_LOGGER() (WPP_CB[0].Control.Logger),
#endif

#endif // WPP_NO_CONTROL_GUIDS

#ifndef WPP_GET_LOGGER
#  define WPP_GET_LOGGER Logger
#endif

#ifndef WPP_LOGGER_ARG
#  define WPP_LOGGER_ARG TRACEHANDLE Logger,
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif // WPP_ALREADY_INCLUDED

// template tracemacro.tpl

// This template expects:
//      WPP_THIS_FILE defined (see header.tpl)
//      WPP_LOGGER_ARG  defined
//      WPP_GET_LOGGER  defined
//      WPP_ENABLED() defined

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WPP_ALREADY_INCLUDED

#undef WPP_LOCAL_TraceGuids
#undef WPP_INVOKE_WPP_DEBUG

#else // WPP_ALREADY_INCLUDED

#ifndef NO_CHECK_FOR_NULL_STRING
#ifndef WPP_CHECK_FOR_NULL_STRING
#define WPP_CHECK_FOR_NULL_STRING
#endif
#endif // NO_CHECK_FOR_NULL_STRING

#define WPP_FLATTEN(...) __VA_ARGS__
#define WPP_GLUE5(a, b, c, d, e)  a ## b ## c ## d ## e
#define WPP_XGLUE5(a, b, c, d, e)  WPP_GLUE5(a, b, c, d, e)
#define WPP_(Id) WPP_XGLUE5(WPP_, Id, _, WPP_THIS_FILE, __LINE__)

#ifndef WPP_INLINE
#define WPP_INLINE DECLSPEC_NOINLINE __inline
#endif

#ifndef WPP_FORCEINLINE
#define WPP_FORCEINLINE __forceinline
#endif

#endif // WPP_ALREADY_INCLUDED

#ifdef WPP_NO_ANNOTATIONS

#define WPP_ANNOTATE(x)

#else // WPP_NO_ANNOTATIONS

#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1361
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1367
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1383
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1384
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1385
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1386
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1387
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1388
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1398
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1399
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1400
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1401
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1402
#endif
#ifdef WPP_PUBLIC_
#define WPP_PUBLIC_ANNOT_Trace_h1403
#endif
#ifdef WPP_EMIT_FUNC_NAME
#define WPP_FUNC_NAME L" FUNC=" _WPPW(__FUNCTION__)
#else // WPP_EMIT_FUNC_NAME
#define WPP_FUNC_NAME
#endif // WPP_EMIT_FUNC_NAME

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1361_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 10 \"%0--> %10!s!\" //   TRACELEVEL=TRACE_LEVEL_VERBOSE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1361_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 10 \"%0--> %10!s!\" //   TRACELEVEL=TRACE_LEVEL_VERBOSE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1361
# define WPP_ANNOTATE_Trace_h1361 WPP_ANNOTATE_Trace_h1361_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1361
# define WPP_ANNOTATE_Trace_h1361 WPP_ANNOTATE_Trace_h1361_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1361", \
    L"{", \
    L"szFunction, ItemString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1361

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1367_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 11 \"%0<-- %10!s!\" //   TRACELEVEL=TRACE_LEVEL_VERBOSE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1367_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 11 \"%0<-- %10!s!\" //   TRACELEVEL=TRACE_LEVEL_VERBOSE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1367
# define WPP_ANNOTATE_Trace_h1367 WPP_ANNOTATE_Trace_h1367_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1367
# define WPP_ANNOTATE_Trace_h1367 WPP_ANNOTATE_Trace_h1367_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1367", \
    L"{", \
    L"szFunction, ItemString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1367

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1383_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 12 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_NONE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1383_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 12 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_NONE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1383
# define WPP_ANNOTATE_Trace_h1383 WPP_ANNOTATE_Trace_h1383_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1383
# define WPP_ANNOTATE_Trace_h1383 WPP_ANNOTATE_Trace_h1383_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1383", \
    L"{", \
    L"trace::_str(sz. cch), ItemPString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1383

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1384_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 13 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_CRITICAL" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1384_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 13 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_CRITICAL" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1384
# define WPP_ANNOTATE_Trace_h1384 WPP_ANNOTATE_Trace_h1384_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1384
# define WPP_ANNOTATE_Trace_h1384 WPP_ANNOTATE_Trace_h1384_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1384", \
    L"{", \
    L"trace::_str(sz. cch), ItemPString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1384

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1385_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 14 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_ERROR" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1385_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 14 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_ERROR" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1385
# define WPP_ANNOTATE_Trace_h1385 WPP_ANNOTATE_Trace_h1385_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1385
# define WPP_ANNOTATE_Trace_h1385 WPP_ANNOTATE_Trace_h1385_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1385", \
    L"{", \
    L"trace::_str(sz. cch), ItemPString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1385

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1386_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 15 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_WARNING" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1386_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 15 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_WARNING" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1386
# define WPP_ANNOTATE_Trace_h1386 WPP_ANNOTATE_Trace_h1386_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1386
# define WPP_ANNOTATE_Trace_h1386 WPP_ANNOTATE_Trace_h1386_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1386", \
    L"{", \
    L"trace::_str(sz. cch), ItemPString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1386

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1387_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 16 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_INFORMATION" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1387_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 16 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_INFORMATION" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1387
# define WPP_ANNOTATE_Trace_h1387 WPP_ANNOTATE_Trace_h1387_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1387
# define WPP_ANNOTATE_Trace_h1387 WPP_ANNOTATE_Trace_h1387_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1387", \
    L"{", \
    L"trace::_str(sz. cch), ItemPString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1387

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1388_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 17 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_VERBOSE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1388_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 17 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_VERBOSE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1388
# define WPP_ANNOTATE_Trace_h1388 WPP_ANNOTATE_Trace_h1388_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1388
# define WPP_ANNOTATE_Trace_h1388 WPP_ANNOTATE_Trace_h1388_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1388", \
    L"{", \
    L"trace::_str(sz. cch), ItemPString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1388

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1398_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 18 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_NONE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1398_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 18 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_NONE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1398
# define WPP_ANNOTATE_Trace_h1398 WPP_ANNOTATE_Trace_h1398_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPWString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1398
# define WPP_ANNOTATE_Trace_h1398 WPP_ANNOTATE_Trace_h1398_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1398", \
    L"{", \
    L"trace::_wstr(sz. cch), ItemPWString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1398

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1399_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 19 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_CRITICAL" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1399_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 19 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_CRITICAL" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1399
# define WPP_ANNOTATE_Trace_h1399 WPP_ANNOTATE_Trace_h1399_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPWString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1399
# define WPP_ANNOTATE_Trace_h1399 WPP_ANNOTATE_Trace_h1399_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1399", \
    L"{", \
    L"trace::_wstr(sz. cch), ItemPWString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1399

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1400_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 20 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_ERROR" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1400_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 20 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_ERROR" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1400
# define WPP_ANNOTATE_Trace_h1400 WPP_ANNOTATE_Trace_h1400_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPWString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1400
# define WPP_ANNOTATE_Trace_h1400 WPP_ANNOTATE_Trace_h1400_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1400", \
    L"{", \
    L"trace::_wstr(sz. cch), ItemPWString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1400

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1401_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 21 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_WARNING" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1401_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 21 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_WARNING" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1401
# define WPP_ANNOTATE_Trace_h1401 WPP_ANNOTATE_Trace_h1401_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPWString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1401
# define WPP_ANNOTATE_Trace_h1401 WPP_ANNOTATE_Trace_h1401_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1401", \
    L"{", \
    L"trace::_wstr(sz. cch), ItemPWString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1401

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1402_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 22 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_INFORMATION" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1402_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 22 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_INFORMATION" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1402
# define WPP_ANNOTATE_Trace_h1402 WPP_ANNOTATE_Trace_h1402_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPWString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1402
# define WPP_ANNOTATE_Trace_h1402 WPP_ANNOTATE_Trace_h1402_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1402", \
    L"{", \
    L"trace::_wstr(sz. cch), ItemPWString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1402

#ifdef WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1403_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    WPP_GUID_WTEXT WPP_USER_MSG_GUID L"Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 23 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_VERBOSE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#else // WPP_USER_MSG_GUID
# define WPP_ANNOTATE_Trace_h1403_FINAL(P, File, Name, ...) __annotation( \
    L ## P, \
    L"01056d4d-ab5f-3412-11c6-0e8778f1f748 Trace // SRC=" _WPPW(File) \
    L" MJ= MN=", \
    L"#typev " _WPPW(Name) \
    L" 23 \"%0%10!s!\" //   TRACELEVEL=TRACE_LEVEL_VERBOSE" \
    WPP_FUNC_NAME, \
    __VA_ARGS__)
#endif // WPP_USER_MSG_GUID

#ifdef WPP_PUBLIC_ANNOT_Trace_h1403
# define WPP_ANNOTATE_Trace_h1403 WPP_ANNOTATE_Trace_h1403_FINAL( \
    "TMF:", \
    "Unknown_cxx00", \
    "Unknown_cxx00", \
    L"{", \
    L"Arg, ItemPWString -- 10" , \
    L"}", \
    L"PUBLIC_TMF:")
# ifndef WPP_PUBLIC_TMC
#  define WPP_PUBLIC_TMC // Adds "PUBLIC_TMF:" to the control guid annotation
# endif
#else // WPP_PUBLIC_ANNOT_Trace_h1403
# define WPP_ANNOTATE_Trace_h1403 WPP_ANNOTATE_Trace_h1403_FINAL( \
    "TMF:", \
    "Trace.h", \
    "Trace_h1403", \
    L"{", \
    L"trace::_wstr(sz. cch), ItemPWString -- 10" , \
    L"}")
#endif // WPP_PUBLIC_ANNOT_Trace_h1403

# define WPP_ANNOTATE(x) WPP_ANNOTATE_ ## x,

#endif // WPP_NO_ANNOTATIONS

#ifdef WPP_USER_MSG_GUID

#define WPP_LOCAL_MSG_VAR(Guid) WPP_XGLUE3(WPP_, WPP_GUID_NORM Guid, _Traceguids)

#define WPP_LOCAL_MSG_GUID(Guid) \
extern const __declspec(selectany) GUID WPP_LOCAL_MSG_VAR(Guid)[] = { WPP_GUID_STRUCT Guid }

WPP_LOCAL_MSG_GUID(WPP_USER_MSG_GUID);
#define WPP_LOCAL_TraceGuids WPP_LOCAL_MSG_VAR(WPP_USER_MSG_GUID)

#else // WPP_USER_MSG_GUID

#define WPP_LOCAL_TraceGuids WPP_01056d4dab5f341211c60e8778f1f748_Traceguids
extern const __declspec(selectany) GUID WPP_LOCAL_TraceGuids[] = { {0x01056d4d,0xab5f,0x3412,{0x11,0xc6,0x0e,0x87,0x78,0xf1,0xf7,0x48}}, };

#endif // WPP_USER_MSG_GUID

#ifndef WPP_ALREADY_INCLUDED

#ifndef WPP_TRACE_OPTIONS
enum { WPP_TRACE_OPTIONS =
    TRACE_MESSAGE_SEQUENCE   |
    TRACE_MESSAGE_GUID       |
    TRACE_MESSAGE_SYSTEMINFO |
    TRACE_MESSAGE_TIMESTAMP };
#endif // WPP_TRACE_OPTIONS

#ifndef WPP_LOGPAIR_SEPARATOR
# define WPP_LOGPAIR_SEPARATOR ,
#endif
#ifndef WPP_LOGPAIR_SIZET
# define WPP_LOGPAIR_SIZET SIZE_T
#endif
#ifndef WPP_LOGPAIR
# define WPP_LOGPAIR(_Size, _Addr)     (_Addr),((WPP_LOGPAIR_SIZET)(_Size))WPP_LOGPAIR_SEPARATOR
#endif

#define WPP_LOGTYPEVAL(_Type, _Value) WPP_LOGPAIR(sizeof(_Type), &(_Value))
#define WPP_LOGTYPEPTR(_Value)        WPP_LOGPAIR(sizeof(*(_Value)), (_Value))

// Marshalling macros.

#ifndef WPP_LOGASTR
# ifdef WPP_CHECK_FOR_NULL_STRING
#  define WPP_LOGASTR(_value)  WPP_LOGPAIR( \
    (_value) ? strlen(_value) + 1 : 5, \
    (_value) ?       (_value)     : "NULL" )
# else // WPP_CHECK_FOR_NULL_STRING
#  define WPP_LOGASTR(_value)  WPP_LOGPAIR( \
    strlen(_value) + 1, \
    _value )
# endif // WPP_CHECK_FOR_NULL_STRING
#endif // WPP_LOGASTR

#ifndef WPP_LOGWSTR
# ifdef WPP_CHECK_FOR_NULL_STRING
#  define WPP_LOGWSTR(_value)  WPP_LOGPAIR( \
    ((_value) ? wcslen(_value) + 1 : 5) * sizeof(WCHAR), \
     (_value) ?       (_value)     : L"NULL" )
# else // WPP_CHECK_FOR_NULL_STRING
#  define WPP_LOGWSTR(_value)  WPP_LOGPAIR( \
    (wcslen(_value) + 1) * sizeof(WCHAR), \
    _value )
# endif // WPP_CHECK_FOR_NULL_STRING
#endif // WPP_LOGWSTR

#ifndef WPP_LOGPGUID
# define WPP_LOGPGUID(_value) WPP_LOGPAIR( sizeof(GUID), (_value) )
#endif // WPP_LOGPGUID

#ifndef WPP_LOGPSID
# ifdef WPP_CHECK_FOR_NULL_STRING
# define WPP_LOGPSID(_value)  WPP_LOGPAIR( \
    (_value) && WPP_IsValidSid(_value) ? WPP_GetLengthSid(_value) : 5, \
    (_value) && WPP_IsValidSid(_value) ? (_value) : (void const*)"NULL")
# else // WPP_CHECK_FOR_NULL_STRING
# define WPP_LOGPSID(_value)  WPP_LOGPAIR( \
    WPP_GetLengthSid(_value), \
    (_value) )
#endif // WPP_CHECK_FOR_NULL_STRING
#endif // WPP_LOGPSID

#ifndef WPP_LOGCSTR
# define WPP_LOGCSTR(_x) \
    WPP_LOGPAIR( sizeof(USHORT),      &(_x).Length ) \
    WPP_LOGPAIR( (USHORT)(_x).Length, (USHORT)(_x).Length ? (_x).Buffer : "" )
#endif // WPP_LOGCSTR

#ifndef WPP_LOGUSTR
# define WPP_LOGUSTR(_x) \
    WPP_LOGPAIR( sizeof(USHORT),      &(_x).Length ) \
    WPP_LOGPAIR( (USHORT)(_x).Length, (USHORT)(_x).Length ? (_x).Buffer : L"" )
#endif // WPP_LOGUSTR

#ifndef WPP_LOGPUSTR
#ifdef WPP_CHECK_FOR_NULL_STRING
# define WPP_LOGPUSTR(_x) \
    WPP_LOGPAIR( \
        sizeof(USHORT), \
        (_x) ? &(_x)->Length : (void const*)L"\x08" ) \
    WPP_LOGPAIR( \
        (_x)                         ? (USHORT)(_x)->Length : 0x08, \
        (_x) && (USHORT)(_x)->Length ? (_x)->Buffer         : L"NULL" )
#else // WPP_CHECK_FOR_NULL_STRING
# define WPP_LOGPUSTR(_x) WPP_LOGUSTR(*(_x))
#endif // WPP_CHECK_FOR_NULL_STRING
#endif // WPP_LOGPUSTR

#ifndef WPP_LOGPCSTR
#ifdef WPP_CHECK_FOR_NULL_STRING
# define WPP_LOGPCSTR(_x) \
    WPP_LOGPAIR( \
        sizeof(USHORT), \
        (_x) ? &(_x)->Length : (void const*)L"\x04" ) \
    WPP_LOGPAIR( \
        (_x)                         ? (USHORT)(_x)->Length : 0x04, \
        (_x) && (USHORT)(_x)->Length ? (_x)->Buffer         : "NULL" )
#else // WPP_CHECK_FOR_NULL_STRING
# define WPP_LOGPCSTR(_x) WPP_LOGCSTR(*(_x))
#endif // WPP_CHECK_FOR_NULL_STRING
#endif // WPP_LOGPCSTR

#ifdef __cplusplus

#ifndef WPP_POINTER_TO_USHORT
struct WppPointerToUshort
{
    USHORT m_val;
    WPP_FORCEINLINE explicit WppPointerToUshort(USHORT val) : m_val(val) {}
    WPP_FORCEINLINE USHORT const* get() const { return &m_val; }
};
#define WPP_POINTER_TO_USHORT(val) (WppPointerToUshort((val)).get())
#endif // WPP_POINTER_TO_USHORT

#ifndef WPP_LOGCPPSTR
#define WPP_LOGCPPSTR(_value) \
    WPP_LOGPAIR( \
        sizeof(USHORT), \
        WPP_POINTER_TO_USHORT((USHORT)((_value).size()*sizeof(*(_value).c_str()))) ) \
    WPP_LOGPAIR( \
        (USHORT)((_value).size()*sizeof(*(_value).c_str())), \
        (_value).c_str() )
#endif // WPP_LOGCPPSTR

#ifndef WPP_LOGCPPVEC
#define WPP_LOGCPPVEC(_value) \
    WPP_LOGPAIR( \
        sizeof(USHORT), \
        WPP_POINTER_TO_USHORT((USHORT)((_value).size()*sizeof(*(_value).data()))) ) \
    WPP_LOGPAIR( \
        (USHORT)((_value).size()*sizeof(*(_value).data())), \
        (_value).data() + ((_value).data() == NULL) )
#endif // WPP_LOGCPPVEC

#endif // __cplusplus

#ifndef WPP_BINARY_def
# define WPP_BINARY_def
typedef struct tagWPP_BINARY
{
    _Field_size_bytes_(Length) void const* Buffer;
    USHORT Length;
} WPP_BINARY;
#endif // WPP_BINARY_def

#ifndef WPP_BINARY_func
# define WPP_BINARY_func
WPP_FORCEINLINE WPP_BINARY
WppBinary(_In_reads_bytes_(Length) void const* Buffer, USHORT Length)
{
    WPP_BINARY data;
    data.Buffer = Buffer;
    data.Length = Length;
    return data;
}
#endif // WPP_BINARY_func

#endif // WPP_ALREADY_INCLUDED

#ifndef WPP_ENABLE_FLAG_BIT
#define WPP_ENABLE_FLAG_BIT(flag) (WPP_CB[((flag) >> 16)].Control).Flags[( (0xFFFF & ((flag)-1) ) / 32)] & (1 << ( ((flag)-1) & 31 ))
#endif

#ifndef WPP_SF_s_def
# define WPP_SF_s_def
WPP_INLINE void WPP_SF_s(WPP_LOGGER_ARG unsigned short id, LPCGUID TraceGuid, LPCSTR _a1)
{ WPP_TRACE(WPP_GET_LOGGER, WPP_TRACE_OPTIONS, (LPGUID)TraceGuid, id, WPP_LOGASTR(_a1)  (void*)0); }
#endif // WPP_SF_s_def

#if ENABLE_WPP_RECORDER

#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER

//
// Generate the WPP_RECORDER_AND_TRACE_SF_s function
//
#ifndef WPP_RECORDER_AND_TRACE_SF_s_def
#define WPP_RECORDER_AND_TRACE_SF_s_def
WPP_INLINE
VOID
WPP_RECORDER_AND_TRACE_SF_s(
    WPP_LOGGER_ARG
    BOOLEAN  wppEnabled,
    BOOLEAN  recorderEnabled,
    PVOID    AutoLogContext,
    UCHAR    level,
    ULONG    flags,
    USHORT   id,
    LPCGUID  traceGuid
    , LPCSTR _a1
    )
{
    if (wppEnabled)
    {
        WPP_TRACE( WPP_GET_LOGGER,
                   WPP_TRACE_OPTIONS,
                   (LPGUID)traceGuid,
                   id,
                   WPP_LOGASTR(_a1)  (void*)0);
    }

    if (recorderEnabled)
    {
        WPP_RECORDER( AutoLogContext, level, flags, (LPGUID) traceGuid, id, WPP_LOGASTR(_a1)  (void*)0 );
    }
}
#endif // WPP_RECORDER_AND_TRACE_SF_s_def

#else  // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER

//
// Generate the WPP_RECORDER_SP_s function
//
#ifndef WPP_RECORDER_SF_s_def
#define WPP_RECORDER_SF_s_def
WPP_INLINE
VOID
WPP_RECORDER_SF_s(
    PVOID    AutoLogContext,
    UCHAR    level,
    ULONG    flags,
    USHORT   id,
    LPCGUID  traceGuid
    , LPCSTR _a1
    )
{
    if (WPP_ENABLE_FLAG_BIT(flags) &&
        (WPP_CONTROL(flags).Level >= level))
    {
        WPP_TRACE(
            WPP_CONTROL(flags).Logger,
            WPP_TRACE_OPTIONS,
            (LPGUID)traceGuid,
            id,
            WPP_LOGASTR(_a1)  (void*)0);
    }

    WPP_RECORDER(AutoLogContext, level, flags, (LPGUID) traceGuid, id, WPP_LOGASTR(_a1)  (void*)0);
}
#endif // WPP_RECORDER_SF_s_def

#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER

#endif // ENABLE_WPP_RECORDER

#ifndef WPP_SF_str_def
# define WPP_SF_str_def
WPP_INLINE void WPP_SF_str(WPP_LOGGER_ARG unsigned short id, LPCGUID TraceGuid, const trace::_str & _a1)
{ WPP_TRACE(WPP_GET_LOGGER, WPP_TRACE_OPTIONS, (LPGUID)TraceGuid, id, WPP_LOGCPPVEC(_a1)  (void*)0); }
#endif // WPP_SF_str_def

#if ENABLE_WPP_RECORDER

#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER

//
// Generate the WPP_RECORDER_AND_TRACE_SF_str function
//
#ifndef WPP_RECORDER_AND_TRACE_SF_str_def
#define WPP_RECORDER_AND_TRACE_SF_str_def
WPP_INLINE
VOID
WPP_RECORDER_AND_TRACE_SF_str(
    WPP_LOGGER_ARG
    BOOLEAN  wppEnabled,
    BOOLEAN  recorderEnabled,
    PVOID    AutoLogContext,
    UCHAR    level,
    ULONG    flags,
    USHORT   id,
    LPCGUID  traceGuid
    , const trace::_str & _a1
    )
{
    if (wppEnabled)
    {
        WPP_TRACE( WPP_GET_LOGGER,
                   WPP_TRACE_OPTIONS,
                   (LPGUID)traceGuid,
                   id,
                   WPP_LOGCPPVEC(_a1)  (void*)0);
    }

    if (recorderEnabled)
    {
        WPP_RECORDER( AutoLogContext, level, flags, (LPGUID) traceGuid, id, WPP_LOGCPPVEC(_a1)  (void*)0 );
    }
}
#endif // WPP_RECORDER_AND_TRACE_SF_str_def

#else  // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER

//
// Generate the WPP_RECORDER_SP_str function
//
#ifndef WPP_RECORDER_SF_str_def
#define WPP_RECORDER_SF_str_def
WPP_INLINE
VOID
WPP_RECORDER_SF_str(
    PVOID    AutoLogContext,
    UCHAR    level,
    ULONG    flags,
    USHORT   id,
    LPCGUID  traceGuid
    , const trace::_str & _a1
    )
{
    if (WPP_ENABLE_FLAG_BIT(flags) &&
        (WPP_CONTROL(flags).Level >= level))
    {
        WPP_TRACE(
            WPP_CONTROL(flags).Logger,
            WPP_TRACE_OPTIONS,
            (LPGUID)traceGuid,
            id,
            WPP_LOGCPPVEC(_a1)  (void*)0);
    }

    WPP_RECORDER(AutoLogContext, level, flags, (LPGUID) traceGuid, id, WPP_LOGCPPVEC(_a1)  (void*)0);
}
#endif // WPP_RECORDER_SF_str_def

#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER

#endif // ENABLE_WPP_RECORDER

#ifndef WPP_SF_wstr_def
# define WPP_SF_wstr_def
WPP_INLINE void WPP_SF_wstr(WPP_LOGGER_ARG unsigned short id, LPCGUID TraceGuid, const trace::_wstr& _a1)
{ WPP_TRACE(WPP_GET_LOGGER, WPP_TRACE_OPTIONS, (LPGUID)TraceGuid, id, WPP_LOGCPPVEC(_a1)  (void*)0); }
#endif // WPP_SF_wstr_def

#if ENABLE_WPP_RECORDER

#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER

//
// Generate the WPP_RECORDER_AND_TRACE_SF_wstr function
//
#ifndef WPP_RECORDER_AND_TRACE_SF_wstr_def
#define WPP_RECORDER_AND_TRACE_SF_wstr_def
WPP_INLINE
VOID
WPP_RECORDER_AND_TRACE_SF_wstr(
    WPP_LOGGER_ARG
    BOOLEAN  wppEnabled,
    BOOLEAN  recorderEnabled,
    PVOID    AutoLogContext,
    UCHAR    level,
    ULONG    flags,
    USHORT   id,
    LPCGUID  traceGuid
    , const trace::_wstr& _a1
    )
{
    if (wppEnabled)
    {
        WPP_TRACE( WPP_GET_LOGGER,
                   WPP_TRACE_OPTIONS,
                   (LPGUID)traceGuid,
                   id,
                   WPP_LOGCPPVEC(_a1)  (void*)0);
    }

    if (recorderEnabled)
    {
        WPP_RECORDER( AutoLogContext, level, flags, (LPGUID) traceGuid, id, WPP_LOGCPPVEC(_a1)  (void*)0 );
    }
}
#endif // WPP_RECORDER_AND_TRACE_SF_wstr_def

#else  // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER

//
// Generate the WPP_RECORDER_SP_wstr function
//
#ifndef WPP_RECORDER_SF_wstr_def
#define WPP_RECORDER_SF_wstr_def
WPP_INLINE
VOID
WPP_RECORDER_SF_wstr(
    PVOID    AutoLogContext,
    UCHAR    level,
    ULONG    flags,
    USHORT   id,
    LPCGUID  traceGuid
    , const trace::_wstr& _a1
    )
{
    if (WPP_ENABLE_FLAG_BIT(flags) &&
        (WPP_CONTROL(flags).Level >= level))
    {
        WPP_TRACE(
            WPP_CONTROL(flags).Logger,
            WPP_TRACE_OPTIONS,
            (LPGUID)traceGuid,
            id,
            WPP_LOGCPPVEC(_a1)  (void*)0);
    }

    WPP_RECORDER(AutoLogContext, level, flags, (LPGUID) traceGuid, id, WPP_LOGCPPVEC(_a1)  (void*)0);
}
#endif // WPP_RECORDER_SF_wstr_def

#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER

#endif // ENABLE_WPP_RECORDER

// WPP_LOG_ALWAYS:
// Called for each event: WPP_LOG_ALWAYS(EX, MSG, arg1, arg2, arg3...) Other()
// If defined, the definition needs to include a trailing comma or semicolon.
// In addition, you will need to define a WPP_EX_[args](args...) macro to
// extract any needed information from the other arguments (e.g. LEVEL).
#ifndef WPP_LOG_ALWAYS
#define WPP_LOG_ALWAYS(...)
#endif

// WPP_DEBUG:
// Called for each enabled event: WPP_DEBUG((MSG, arg1, arg2, arg3...)), Other()
// Potential definition: printf MsgArgs
// Definition should not include any trailing comma or semicolon.
#ifdef WPP_DEBUG
#define WPP_INVOKE_WPP_DEBUG(MsgArgs) WPP_DEBUG(MsgArgs)
#else // WPP_DEBUG
#define WPP_INVOKE_WPP_DEBUG(MsgArgs) (void)0
#endif // WPP_DEBUG

// WPP_CALL_Trace_h1361
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1361(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1361) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_s( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     10, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1361(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1361) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_s( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                10, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1361(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1361) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_s( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                10, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1367
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1367(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1367) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_s( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     11, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1367(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1367) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_s( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                11, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1367(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1367) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_s( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                11, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1383
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1383(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1383) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_str( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     12, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1383(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1383) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_str( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                12, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1383(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1383) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_str( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                12, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1384
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1384(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1384) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_str( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     13, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1384(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1384) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_str( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                13, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1384(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1384) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_str( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                13, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1385
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1385(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1385) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_str( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     14, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1385(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1385) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_str( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                14, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1385(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1385) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_str( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                14, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1386
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1386(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1386) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_str( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     15, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1386(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1386) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_str( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                15, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1386(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1386) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_str( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                15, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1387
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1387(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1387) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_str( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     16, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1387(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1387) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_str( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                16, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1387(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1387) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_str( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                16, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1388
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1388(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1388) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_str( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     17, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1388(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1388) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_str( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                17, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1388(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1388) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_str( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                17, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1398
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1398(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1398) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_wstr( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     18, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1398(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1398) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_wstr( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                18, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1398(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1398) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_wstr( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                18, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1399
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1399(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1399) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_wstr( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     19, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1399(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1399) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_wstr( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                19, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1399(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1399) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_wstr( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                19, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1400
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1400(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1400) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_wstr( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     20, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1400(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1400) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_wstr( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                20, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1400(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1400) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_wstr( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                20, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1401
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1401(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1401) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_wstr( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     21, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1401(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1401) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_wstr( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                21, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1401(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1401) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_wstr( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                21, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1402
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1402(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1402) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_wstr( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     22, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1402(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1402) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_wstr( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                22, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1402(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1402) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_wstr( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                22, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// WPP_CALL_Trace_h1403
#ifndef WPP_TRACELEVEL_PRE
#  define WPP_TRACELEVEL_PRE(TRACELEVEL)
#endif
#ifndef WPP_TRACELEVEL_POST
#  define WPP_TRACELEVEL_POST(TRACELEVEL)
#endif
#if ENABLE_WPP_RECORDER
#if ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1403(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    do {\
        WPP_ANNOTATE(Trace_h1403) 0; \
        BOOLEAN wppEnabled = WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL); \
        BOOLEAN recorderEnabled = WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL); \
        if (wppEnabled || recorderEnabled) { \
            WPP_INVOKE_WPP_DEBUG((MSG, _a10)); \
            WPP_RECORDER_AND_TRACE_SF_wstr( \
                     WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                     wppEnabled, recorderEnabled, \
                     WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                     23, \
                     WPP_LOCAL_TraceGuids+0, _a10);\
        } \
    } \
    while(0) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#else // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#define WPP_CALL_Trace_h1403(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1403) \
    (( \
        WPP_RECORDER_CHECK_INIT WPP_RECORDER_TRACELEVEL_FILTER(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_RECORDER_SF_wstr( \
                WPP_RECORDER_TRACELEVEL_ARGS(TRACELEVEL), \
                23, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_TRACE_FILTERING_WITH_WPP_RECORDER
#else  // ENABLE_WPP_RECORDER
#define WPP_CALL_Trace_h1403(TRACELEVEL, MSG, _a10) \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(TRACELEVEL), MSG, _a10) \
    WPP_TRACELEVEL_PRE(TRACELEVEL) \
    WPP_ANNOTATE(Trace_h1403) \
    (( \
        WPP_CHECK_INIT WPP_TRACELEVEL_ENABLED(TRACELEVEL) \
        ?   WPP_INVOKE_WPP_DEBUG((MSG, _a10)), \
            WPP_SF_wstr( \
                WPP_TRACELEVEL_LOGGER(TRACELEVEL) \
                23, \
                WPP_LOCAL_TraceGuids+0, _a10), \
            1 \
        :   0 \
    )) \
    WPP_TRACELEVEL_POST(TRACELEVEL)
#endif // ENABLE_WPP_RECORDER

// Functions
#undef AE_CHECK_COM
#define AE_CHECK_COM WPP_(CALL)
#undef AE_CHECK_HRESULT
#define AE_CHECK_HRESULT WPP_(CALL)
#undef AE_CHECK_LIBPQ
#define AE_CHECK_LIBPQ WPP_(CALL)
#undef AE_CHECK_NTSTATUS
#define AE_CHECK_NTSTATUS WPP_(CALL)
#undef AE_CHECK_OCI
#define AE_CHECK_OCI WPP_(CALL)
#undef AE_CHECK_ODBC
#define AE_CHECK_ODBC WPP_(CALL)
#undef AE_CHECK_OPENSSL
#define AE_CHECK_OPENSSL WPP_(CALL)
#undef AE_CHECK_PKCS11
#define AE_CHECK_PKCS11 WPP_(CALL)
#undef AE_CHECK_POSIX
#define AE_CHECK_POSIX WPP_(CALL)
#undef AE_CHECK_PYTHON
#define AE_CHECK_PYTHON WPP_(CALL)
#undef AE_CHECK_SYSAPI
#define AE_CHECK_SYSAPI WPP_(CALL)
#undef AE_CHECK_WINAPI
#define AE_CHECK_WINAPI WPP_(CALL)
#undef AE_CHECK_WINERROR
#define AE_CHECK_WINERROR WPP_(CALL)
#undef AE_CHECK_WINSOCK
#define AE_CHECK_WINSOCK WPP_(CALL)
#undef AE_RAISE_GENERIC
#define AE_RAISE_GENERIC WPP_(CALL)
#undef ATRACE
#define ATRACE WPP_(CALL)
#undef DoDebugTrace
#define DoDebugTrace WPP_(CALL)
#undef DoTraceMessage
#define DoTraceMessage WPP_(CALL)

#ifdef __cplusplus
} // extern "C"
#endif

