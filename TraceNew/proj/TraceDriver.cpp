// При обработке исходного файла утилитой ТraceWpp создается TMH-файл, 
// содержащий дополнительные определения, требуемые для трассировки. Среди 
// указанных определений будут следующие (на основе приведенного значения
// WPP_CONTROL_GUIDS): 
// 
#include <ntddk.h>
#include <evntrace.h>
#include <stddef.h>
#include <stdarg.h>
#include <wmistr.h>

// назначение провайдерам порядковых номеров 
enum WPP_CTL_NAMES { WPP_CTL_Regular, WPP_CTL_HiFreq, WPP_LAST_CTL };
 
// C-определения GUID провайдеров
extern "C" extern __declspec(selectany) const GUID WPP_ThisDir_CTLGUID_Regular = {
    0x81b20fea, 0x73a8, 0x4b62, { 
        (((ULONGLONG)(0x95bc        ) >> (8 * 1)) & 0xFF), 
        (((ULONGLONG)(0x95bc        ) >> (8 * 0)) & 0xFF), 
        (((ULONGLONG)(0x354477c97a6f) >> (8 * 5)) & 0xFF), 
        (((ULONGLONG)(0x354477c97a6f) >> (8 * 4)) & 0xFF), 
        (((ULONGLONG)(0x354477c97a6f) >> (8 * 3)) & 0xFF), 
        (((ULONGLONG)(0x354477c97a6f) >> (8 * 2)) & 0xFF), 
        (((ULONGLONG)(0x354477c97a6f) >> (8 * 1)) & 0xFF), 
        (((ULONGLONG)(0x354477c97a6f) >> (8 * 0)) & 0xFF)
    }
};   
extern "C" extern __declspec(selectany) const GUID WPP_ThisDir_CTLGUID_HiFreq = {
    0x91b20fea, 0x73a8, 0x4b62, { 
         (((ULONGLONG)(0x95bc        ) >> (8 * 1)) & 0xFF), 
         (((ULONGLONG)(0x95bc        ) >> (8 * 0)) & 0xFF), 
         (((ULONGLONG)(0x354477c97a6f) >> (8 * 5)) & 0xFF), 
         (((ULONGLONG)(0x354477c97a6f) >> (8 * 4)) & 0xFF), 
         (((ULONGLONG)(0x354477c97a6f) >> (8 * 3)) & 0xFF), 
         (((ULONGLONG)(0x354477c97a6f) >> (8 * 2)) & 0xFF), 
         (((ULONGLONG)(0x354477c97a6f) >> (8 * 1)) & 0xFF), 
         (((ULONGLONG)(0x354477c97a6f) >> (8 * 0)) & 0xFF)
    }
};  
// назначение уникальных номеров всем категориям сообщений провайдеров
enum WPP_DEFINE_BIT_NAMES {  
      WPP_BLOCK_START_Regular = WPP_CTL_Regular * 0x10000,    /* 0x00000 */
      WPP_BIT_Error,                                          /* 0x00001 */
      WPP_BIT_Unusual,                                        /* 0x00002 */
      WPP_BIT_Noise,                                          /* 0x00003 */
      WPP_BLOCK_END_Regular,                                  /* 0x00004 */
      WPP_BLOCK_START_HiFreq = WPP_CTL_HiFreq * 0x10000,      /* 0x10000 */
      WPP_BIT_Entry,                                          /* 0x10001 */
      WPP_BIT_Exit,                                           /* 0x10002 */
      WPP_BIT_ApiCalls,                                       /* 0x10003 */
      WPP_BIT_RandomJunk,                                     /* 0x10004 */
      WPP_BIT_LovePoem,                                       /* 0x10005 */
      WPP_BLOCK_END_HiFreq,                                   /* 0x10006 */
}; 
// calculate how many DWORDs we need to get the required number of bits
// upper estimate. Sometimes will be off by one
enum _WPP_FLAG_LEN_ENUM { WPP_FLAG_LEN = 
     1 | ((0 | WPP_BLOCK_END_Regular | WPP_BLOCK_END_HiFreq) & 0xFFFF) / 32 
};
// 
// // для дальнейшей проверки максмально допустимого числа категорий провайдера
#define MAX_NUMBER_OF_ETW_FLAGS 34 // 32 flags plus 2 separators
enum _WPP_FLAG_LEN_ENUM_MAX { WPP_MAX_FLAG_LEN_CHECK = (1  
     && ((WPP_BLOCK_END_Regular & 0xFFFF) < MAX_NUMBER_OF_ETW_FLAGS) 
     && ((WPP_BLOCK_END_HiFreq  & 0xFFFF) < MAX_NUMBER_OF_ETW_FLAGS) 
)};

typedef LONG (*WMIENTRY_NEW)(
    _In_ UCHAR MinorFunction,
    _In_opt_ PVOID DataPath,
    _In_ ULONG BufferLength,
    _Inout_updates_bytes_(BufferLength) PVOID Buffer,
    _In_ PVOID Context,
    _Out_ PULONG Size
);
typedef struct _WPP_TRACE_CONTROL_BLOCK {
    WMIENTRY_NEW                        Callback;
    LPCGUID                             ControlGuid;
    struct _WPP_TRACE_CONTROL_BLOCK    *Next;
    __int64                             Logger;
    PUNICODE_STRING                     RegistryPath;
    UCHAR                               FlagsLen;
    UCHAR                               Level;
    USHORT                              Reserved;
    ULONG                               Flags[1];
    ULONG                               ReservedFlags;
    REGHANDLE                           RegHandle;
} WPP_TRACE_CONTROL_BLOCK, *PWPP_TRACE_CONTROL_BLOCK;

#ifndef WPP_CB_TYPE
#define WPP_CB_TYPE WPP_PROJECT_CONTROL_BLOCK
#endif
#ifndef WPP_CB
#define WPP_CB      WPP_GLOBAL_Control
#endif

typedef union {
    WPP_TRACE_CONTROL_BLOCK Control;
    UCHAR ReserveSpace[sizeof(WPP_TRACE_CONTROL_BLOCK) + sizeof(ULONG) * (WPP_FLAG_LEN - 1)];
} WPP_PROJECT_CONTROL_BLOCK;

extern "C" extern __declspec(selectany) WPP_CB_TYPE* WPP_CB = (WPP_CB_TYPE*)&WPP_CB;

#ifndef WPP_CHECK_INIT
#define WPP_CHECK_INIT (WPP_CB != (WPP_CB_TYPE*)&WPP_CB) &&
#endif
 
typedef enum _WPP_TRACE_API_SUITE {
    WppTraceDisabledSuite,
    WppTraceWin2K,
    WppTraceWinXP,
    WppTraceTraceLH,
    WppTraceServer08,
    WppTraceMaxSuite
} WPP_TRACE_API_SUITE;
extern "C" __declspec(selectany) 
    WPP_TRACE_API_SUITE WPPTraceSuite = WppTraceDisabledSuite;

typedef BOOLEAN NTKERNELAPI (FN_WPPGETVERSION)(
    _Out_opt_ PULONG MajorVersion,
    _Out_opt_ PULONG MinorVersion,
    _Out_opt_ PULONG BuildNumber,
    _Out_opt_ PUNICODE_STRING CSDVersion
);
typedef FN_WPPGETVERSION *PFN_WPPGETVERSION;
extern "C" __declspec(selectany) 
    PFN_WPPGETVERSION pfnWppGetVersion = NULL;

typedef LONG (*PFN_WPPQUERYTRACEINFORMATION) (
    IN  TRACE_INFORMATION_CLASS TraceInformationClass,
    OUT PVOID  TraceInformation,
    IN  ULONG  TraceInformationLength,
    OUT PULONG RequiredLength OPTIONAL,
    IN  PVOID  Buffer OPTIONAL
);
extern "C" __declspec(selectany) 
    PFN_WPPQUERYTRACEINFORMATION pfnWppQueryTraceInformation = NULL;

typedef LONG (*PFN_WPPTRACEMESSAGE)(
    IN ULONG64  LoggerHandle,
    IN ULONG   MessageFlags,
    IN LPCGUID MessageGuid,
    IN USHORT  MessageNumber,
    IN ...
);
extern "C" __declspec(selectany) 
    PFN_WPPTRACEMESSAGE pfnWppTraceMessage = NULL;

_IRQL_requires_same_
typedef VOID (NTAPI *PETW_CLASSIC_CALLBACK)(
    _In_ LPCGUID Guid,
    _In_ UCHAR ControlCode,
    _In_ PVOID EnableContext,
    _In_opt_ PVOID CallbackContext
);
_IRQL_requires_same_
typedef NTSTATUS NTKERNELAPI (FN_ETWREGISTERCLASSICPROVIDER)(
    _In_ LPCGUID ProviderGuid,
    _In_ ULONG Type,
    _In_ PETW_CLASSIC_CALLBACK EnableCallback,
    _In_opt_ PVOID CallbackContext,
    _Out_ PREGHANDLE RegHandle
);
typedef FN_ETWREGISTERCLASSICPROVIDER *PFN_ETWREGISTERCLASSICPROVIDER;
extern "C" __declspec(selectany) 
    PFN_ETWREGISTERCLASSICPROVIDER pfnEtwRegisterClassicProvider = NULL;

typedef NTSTATUS NTKERNELAPI (FN_ETWUNREGISTER)(
    _In_ REGHANDLE RegHandle
);
typedef FN_ETWUNREGISTER *PFN_ETWUNREGISTER;
extern "C" __declspec(selectany) 
    PFN_ETWUNREGISTER pfnEtwUnregister = NULL;

#ifndef WPP_TRACE
#define WPP_TRACE pfnWppTraceMessage
#endif

extern "C" VOID WppLoadTracingSupport();

extern "C" NTSTATUS WppTraceCallback(
    _In_ UCHAR MinorFunction,
    _In_opt_ PVOID DataPath,
    _In_ ULONG BufferLength,
    _Inout_updates_bytes_(BufferLength) PVOID Buffer,
    _Inout_ PVOID Context,
    _Out_ PULONG Size
);

#if !defined(WPP_TRACE_CONTROL_NULL_GUID)
DEFINE_GUID(WPP_TRACE_CONTROL_NULL_GUID, 0x00000000L, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
#endif

#define WPP_TRACE_CONTROL(Function,Buffer,BufferSize,ReturnSize) WppTraceCallback(Function,NULL,BufferSize,Buffer,&WPP_CB[0],&ReturnSize);

__inline ULONG64 WppQueryLogger(_In_opt_ PCWSTR LoggerName)
{
    if (WppTraceWinXP != WPPTraceSuite) return (ULONG64)0;

    UNICODE_STRING Buffer;
    RtlInitUnicodeString(&Buffer, LoggerName ? LoggerName : L"stdout");

    ULONG64 TraceHandle; ULONG ReturnLength;
    LONG Status = pfnWppQueryTraceInformation(TraceHandleByNameClass, 
        (PVOID)&TraceHandle, sizeof(TraceHandle), &ReturnLength, (PVOID)&Buffer
    );
    if (Status != STATUS_SUCCESS) return (ULONG64)0;

    return TraceHandle;
}

extern "C" VOID WppCleanupKm(_In_opt_ PDRIVER_OBJECT DriverObject);

#define WPP_CLEANUP(DriverObject) WppCleanupKm((PDRIVER_OBJECT)DriverObject)

#define WPP_IsValidSid RtlValidSid
#define WPP_GetLengthSid RtlLengthSid

//
// Callback routine to be defined by the driver, which will be called from WPP callback
// WPP will pass current valued of : GUID, Logger, Enable, Flags, and Level
//
// To activate driver must define WPP_PRIVATE_ENABLE_CALLBACK in their code, sample below
// #define WPP_PRIVATE_ENABLE_CALLBACK MyPrivateCallback;
//
typedef
VOID
(*PFN_WPP_PRIVATE_ENABLE_CALLBACK)(
    _In_ LPCGUID Guid,
    _In_ __int64 Logger,
    _In_ BOOLEAN Enable,
    _In_ ULONG Flags,
    _In_ UCHAR Level);


// template km-init.tpl

#ifndef WPPINIT_EXPORT
#define WPPINIT_EXPORT
#endif

#ifndef WppDebug
#define WppDebug(a,b)
#endif

extern "C" WPPINIT_EXPORT
VOID
WppInitGlobalLogger(
    _In_ LPCGUID ControlGuid,
    _Out_ PTRACEHANDLE LoggerHandle,
    _Out_ PULONG Flags,
    _Out_ PUCHAR Level
    );

extern "C" WPPINIT_EXPORT
VOID
WppInitKm(
    _In_opt_ PDRIVER_OBJECT DriverObject,
    _In_opt_ PCUNICODE_STRING RegPath
    );

#ifdef ALLOC_PRAGMA
    #pragma alloc_text( PAGE, WppLoadTracingSupport)
    #pragma alloc_text( PAGE, WppInitGlobalLogger)
    #pragma alloc_text( PAGE, WppTraceCallback)
    #pragma alloc_text( PAGE, WppInitKm)
    #pragma alloc_text( PAGE, WppCleanupKm)
#endif // ALLOC_PRAGMA

WPP_CB_TYPE WPP_MAIN_CB[WPP_LAST_CTL];

// define annotation record that will carry control information to pdb (in case somebody needs it)
__forceinline void WPP_CONTROL_ANNOTATION() 
{
#ifndef WPP_TMC_ANNOT_SUFIX
#ifdef WPP_PUBLIC_TMC
    #define WPP_TMC_ANNOT_SUFIX ,L"PUBLIC_TMF:"
#else
    #define WPP_TMC_ANNOT_SUFIX
#endif
#endif
    __annotation(L"TMC:", L"81b20fea-73a8-4b62-95bc-354477c97a6f", L"Regular", L"Error", L"Unusual", L"Noise" WPP_TMC_ANNOT_SUFIX);
    __annotation(L"TMC:", L"91b20fea-73a8-4b62-95bc-354477c97a6f", L"HiFreq" , L"Entry", L"Exit", L"ApiCalls", L"RandomJunk", L"LovePoem" WPP_TMC_ANNOT_SUFIX);
}

__inline void WPP_INIT_CONTROL_ARRAY(WPP_CB_TYPE* Arr) 
{
     Arr->Control.Callback = NULL;
     Arr->Control.ControlGuid = &WPP_ThisDir_CTLGUID_Regular;    
     Arr->Control.Next = ((WPP_TRACE_CONTROL_BLOCK*)(
         WPP_CTL_Regular + 1 == WPP_LAST_CTL ? 0 : WPP_MAIN_CB + WPP_CTL_Regular + 1
     )); 
     Arr->Control.RegistryPath= NULL;
     Arr->Control.FlagsLen = WPP_FLAG_LEN;
     Arr->Control.Level = 0;
     Arr->Control.Reserved = 0;
     Arr->Control.Flags[0] = 0;
     ++Arr; 
     Arr->Control.Callback = NULL;
     Arr->Control.ControlGuid = &WPP_ThisDir_CTLGUID_HiFreq;    
     Arr->Control.Next = ((WPP_TRACE_CONTROL_BLOCK*)(
         WPP_CTL_HiFreq + 1 == WPP_LAST_CTL ? 0 : WPP_MAIN_CB + WPP_CTL_HiFreq + 1
     ));
     Arr->Control.RegistryPath= NULL;
     Arr->Control.FlagsLen = WPP_FLAG_LEN;
     Arr->Control.Level = 0;
     Arr->Control.Reserved = 0;
     Arr->Control.Flags[0] = 0;
     ++Arr; 
}
#define WPP_INIT_STATIC_DATA WPP_INIT_CONTROL_ARRAY(WPP_MAIN_CB)

// define WPP_INIT_TRACING.  For performance reasons turn off during
// static analysis compilation with Static Driver Verifier (SDV).
#ifndef _SDV_
#define WPP_INIT_TRACING(DriverObject, RegPath)                             \
    {                                                                       \
      WppDebug(0,("WPP_INIT_TRACING: &WPP_CB[0] %p\n", &WPP_MAIN_CB[0]));   \
      WPP_INIT_STATIC_DATA;                                                 \
      WppLoadTracingSupport();                                              \
      ( WPP_CONTROL_ANNOTATION(),                                           \
        WPP_MAIN_CB[0].Control.RegistryPath = NULL,                         \
        WppInitKm( (PDRIVER_OBJECT)DriverObject, RegPath )                  \
      );                                                                    \
    }
#else
#define WPP_INIT_TRACING(DriverObject, RegPath)
#endif

//
// Public routines to break down the Loggerhandle
//

#if !defined(KERNEL_LOGGER_ID)
#define KERNEL_LOGGER_ID                      0xFFFF    // USHORT only
#endif

__inline int WppIsEqualGuid(_In_ const GUID* g1, _In_ const GUID* g2)
{
    const ULONG* p1 = (const ULONG*)g1;
    const ULONG* p2 = (const ULONG*)g2;
    return p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2] && p1[3] == p2[3];
}

extern "C" VOID WppLoadTracingSupport()
/*++

Routine Description:

    This function assigns at runtime the ETW API set to be use for tracing.

Arguments:

Remarks:

    At runtime determine assing the funtions pointers for the trace APIs to be use.
    XP and above will use TraceMessage, and Win2K is not supported.

--*/
{
    PAGED_CODE();

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsGetVersion");
    pfnWppGetVersion = (PFN_WPPGETVERSION)
        (INT_PTR) MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"WmiTraceMessage");
    pfnWppTraceMessage = (PFN_WPPTRACEMESSAGE) 
        (INT_PTR) MmGetSystemRoutineAddress(&name);

    //
    // WinXp
    //

    RtlInitUnicodeString(&name, L"WmiQueryTraceInformation");
    pfnWppQueryTraceInformation = (PFN_WPPQUERYTRACEINFORMATION) 
        (INT_PTR) MmGetSystemRoutineAddress(&name);

    WPPTraceSuite = WppTraceWinXP;

    //
    // Server08
    //

    ULONG MajorVersion = 0;
    if (pfnWppGetVersion != NULL) {
        pfnWppGetVersion(&MajorVersion, NULL, NULL, NULL);
    }
    if (MajorVersion >= 6) 
    {
        RtlInitUnicodeString(&name, L"EtwRegisterClassicProvider");
        pfnEtwRegisterClassicProvider = (PFN_ETWREGISTERCLASSICPROVIDER)
            (INT_PTR) MmGetSystemRoutineAddress(&name);

        if (pfnEtwRegisterClassicProvider != NULL) 
        {
            //
            // For Vista SP1 and later
            //
            RtlInitUnicodeString(&name, L"EtwUnregister");
            pfnEtwUnregister = (PFN_ETWUNREGISTER) 
                (INT_PTR) MmGetSystemRoutineAddress(&name);

            WPPTraceSuite = WppTraceServer08;
        }
    }
}

#define WPP_GLOBALLOGGER
#ifdef WPP_GLOBALLOGGER
#define DEFAULT_GLOBAL_LOGGER_KEY       L"WMI\\GlobalLogger\\"
#define WPP_TEXTGUID_LEN 38                             // размер "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
#define GREGVALUENAMELENGTH (18 + WPP_TEXTGUID_LEN)     // wсslen(L"WMI\\GlobalLogger\\") + GUIDLENGTH

extern "C" WPPINIT_EXPORT VOID WppInitGlobalLogger(
    _In_ LPCGUID ControlGuid,
    _Out_ PTRACEHANDLE LoggerHandle,
    _Out_ PULONG Flags,
    _Out_ PUCHAR Level
)
{
   PAGED_CODE();

   WppDebug(0, ("WPP checking Global Logger\n"));


    RTL_QUERY_REGISTRY_TABLE Parms[3]; ULONG Zero = 0;

   //
   // Fill in the query table to find out if the Global Logger is Started
   //
   // Trace Flags
    ULONG Start = 0;
    Parms[0].QueryRoutine  = NULL;
    Parms[0].Flags         = RTL_QUERY_REGISTRY_DIRECT;   // запросить значение
    Parms[0].Name          = L"Start";                    // имя параметра
    Parms[0].EntryContext  = &Start;                      // буфер для значения
    Parms[0].DefaultType   = REG_DWORD;                   // тип значения
    Parms[0].DefaultData   = &Zero;                       // значение по умолчанию 
    Parms[0].DefaultLength = sizeof(ULONG);               // размер значения по умолчанию

    // Termination
    Parms[1].QueryRoutine  = NULL;
    Parms[1].Flags         = 0;
   //
   // Perform the query
   //
   NTSTATUS Status = RtlQueryRegistryValues(
       RTL_REGISTRY_CONTROL | RTL_REGISTRY_OPTIONAL,
       DEFAULT_GLOBAL_LOGGER_KEY, Parms, NULL, NULL
    );
    if (!NT_SUCCESS(Status) || Start == 0) return;

    UNICODE_STRING GuidString;
    Status = RtlStringFromGUID(*ControlGuid, &GuidString);
    if (Status != STATUS_SUCCESS) {
        WppDebug(0, ("WPP GlobalLogger failed RtlStringFromGUID \n"));
        return;
    }
    if (GuidString.Length > (WPP_TEXTGUID_LEN * sizeof(WCHAR)))
    {
        WppDebug(0, ("WPP GlobalLogger RtlStringFromGUID  too large\n"));
        RtlFreeUnicodeString(&GuidString); return;
     }

    WCHAR GRegValueName[GREGVALUENAMELENGTH];
    RtlCopyMemory(GRegValueName, DEFAULT_GLOBAL_LOGGER_KEY,  
        (wcslen(DEFAULT_GLOBAL_LOGGER_KEY) + 1) *sizeof(WCHAR)
    );
    // got the GUID in form "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
    // need GUID in form "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    // copy the translated GUID string
    RtlCopyMemory(&GRegValueName[(ULONG)wcslen(GRegValueName)], 
        &GuidString.Buffer[1], GuidString.Length
    );
    GRegValueName[(ULONG)wcslen(GRegValueName) - 1] = L'\0';
    RtlFreeUnicodeString(&GuidString);

    // Fill in the query table to find out if we should use the Global logger
    //
    // Trace Flags
    ULONG CurrentFlags = 0;
    Parms[0].QueryRoutine  = NULL;
    Parms[0].Flags         = RTL_QUERY_REGISTRY_DIRECT;
    Parms[0].Name          = L"Flags";
    Parms[0].EntryContext  = &CurrentFlags;
    Parms[0].DefaultType   = REG_DWORD;
    Parms[0].DefaultData   = &Zero;
    Parms[0].DefaultLength = sizeof(ULONG);
    
    // Trace level
    ULONG CurrentLevel = 0;
    Parms[1].QueryRoutine  = NULL;
    Parms[1].Flags         = RTL_QUERY_REGISTRY_DIRECT;
    Parms[1].Name          = L"Level";
    Parms[1].EntryContext  = &CurrentLevel;
    Parms[1].DefaultType   = REG_DWORD;
    Parms[1].DefaultData   = &Zero;
    Parms[1].DefaultLength = sizeof(UCHAR);
    
    // Termination
    Parms[2].QueryRoutine  = NULL;
    Parms[2].Flags         = 0;

   Status = RtlQueryRegistryValues(
       RTL_REGISTRY_CONTROL | RTL_REGISTRY_OPTIONAL,
       GRegValueName, Parms, NULL, NULL
   );
    if (!NT_SUCCESS(Status)) 
    {
        WppDebug(0, ("WPP GlobalLogger has No Flags/Levels Status=%08X\n", Status));
    }
    else if (Start==1) { *LoggerHandle= WMI_GLOBAL_LOGGER_ID;

        *Flags = CurrentFlags & 0x7FFFFFFF; *Level = (UCHAR)(CurrentLevel & 0xFF);

        WppDebug(0, ("WPP Enabled via Global Logger Flags=0x%08X Level=0x%02X\n", CurrentFlags, CurrentLevel));
    } 
    else WppDebug(0, ("WPP GlobalLogger has No Flags/Levels Status=%08X\n", Status));
}
#endif

#define WPP_MAX_COUNT_REGISTRATION_GUID 63

typedef struct _WPP_TRACE_ENABLE_CONTEXT {
    USHORT  LoggerId;           // Actual Id of the logger
    UCHAR   Level;              // Enable level passed by control caller
    UCHAR   InternalFlag;       // Reserved
    ULONG   EnableFlags;        // Enable flags passed by control caller
} WPP_TRACE_ENABLE_CONTEXT, *PWPP_TRACE_ENABLE_CONTEXT;

#if !defined(WmiGetLoggerId)
#define WmiGetLoggerId(LoggerContext) \
    (((PWPP_TRACE_ENABLE_CONTEXT) (&LoggerContext))->LoggerId == \
        (USHORT)KERNEL_LOGGER_ID) ? \
        KERNEL_LOGGER_ID : \
        ((PWPP_TRACE_ENABLE_CONTEXT) (&LoggerContext))->LoggerId

#define WmiGetLoggerEnableFlags(LoggerContext) \
   ((PWPP_TRACE_ENABLE_CONTEXT) (&LoggerContext))->EnableFlags
#define WmiGetLoggerEnableLevel(LoggerContext) \
    ((PWPP_TRACE_ENABLE_CONTEXT) (&LoggerContext))->Level
#endif

extern "C" WPPINIT_EXPORT NTSTATUS WppTraceCallback(
    _In_ UCHAR MinorFunction,
    _In_opt_ PVOID DataPath,
    _In_ ULONG BufferLength,
    _Inout_updates_bytes_(BufferLength) PVOID Buffer,
    _Inout_ PVOID Context,
    _Out_ PULONG Size
    )
/*++

Routine Description:

    This function is the callback WMI calls when we register and when our
    events are enabled or disabled.

Arguments:

    MinorFunction - specifies the type of callback (register, event enable/disable)

    DataPath - varies depending on the ActionCode

    BufferLength - size of the Buffer parameter

    Buffer - in/out buffer where we read from or write to depending on the type
        of callback

    Context - the pointer private struct WPP_TRACE_CONTROL_BLOCK

    Size - output parameter to receive the amount of data written into Buffer

Return Value:

    NTSTATUS code indicating success/failure

Comments:

    if return value is STATUS_BUFFER_TOO_SMALL and BufferLength >= 4,
    then first ulong of buffer contains required size


--*/

{
    UNREFERENCED_PARAMETER(DataPath);

    PAGED_CODE();

    WppDebug(0, ("WppTraceCallBack 0x%08X %p\n", MinorFunction, Context));

    NTSTATUS Status = STATUS_SUCCESS; *Size = 0;

    switch (MinorFunction)
    {
    case IRP_MN_REGINFO:
    {
        //
        // Initialize locals
        //

        PWPP_TRACE_CONTROL_BLOCK cntl = (PWPP_TRACE_CONTROL_BLOCK)Context;
        PWMIREGINFOW WmiRegInfo = (PWMIREGINFO)Buffer;

        PCUNICODE_STRING RegPath = cntl->RegistryPath;

        //
        // Count the number of guid to be identified.
        //
        ULONG GuidCount = 0; for (; cntl; cntl = cntl->Next) GuidCount++; 

        if (GuidCount > WPP_MAX_COUNT_REGISTRATION_GUID)
        {
            Status = STATUS_INVALID_PARAMETER; break;
        }

        WppDebug(0, ("WppTraceCallBack: GUID count %d\n", GuidCount));

        //
        // Calculate buffer size need to hold all info.
        // Calculate offset to where RegistryPath parm will be copied.
        //
        ULONG RegistryPathOffset; ULONG BufferNeeded;
        if (RegPath == NULL) { RegistryPathOffset = 0;

            BufferNeeded = FIELD_OFFSET(WMIREGINFOW, WmiRegGuid) + GuidCount * sizeof(WMIREGGUIDW);

        } else {
            RegistryPathOffset = FIELD_OFFSET(WMIREGINFOW, WmiRegGuid) + GuidCount * sizeof(WMIREGGUIDW);

            BufferNeeded = RegistryPathOffset + RegPath->Length + sizeof(USHORT);
        }

        //
        // If the provided buffer is large enough, then fill with info.
        //

        if (BufferNeeded > BufferLength) { Status = STATUS_BUFFER_TOO_SMALL;

            if (BufferLength >= sizeof(ULONG)) { *Size = sizeof(ULONG);
            
                *((PULONG)Buffer) = BufferNeeded;
            }
        }
        else {
            RtlZeroMemory(Buffer, BufferLength);

            //
            // Fill in the WMIREGINFO
            //
            WmiRegInfo->BufferSize   = BufferNeeded;
            WmiRegInfo->RegistryPath = RegistryPathOffset;
            WmiRegInfo->GuidCount    = GuidCount;

            if (RegPath != NULL) 
            {
                PWCHAR StringPtr = (PWCHAR)((PUCHAR)Buffer + RegistryPathOffset);
                
                *StringPtr++ = RegPath->Length;

                RtlCopyMemory(StringPtr, RegPath->Buffer, RegPath->Length);
            }
            //
            // Fill in the WMIREGGUID
            //
            cntl = (PWPP_TRACE_CONTROL_BLOCK) Context;

            for (ULONG i = 0; i < GuidCount; i++, cntl = cntl->Next) 
            {
                    
                WmiRegInfo->WmiRegGuid[i].Guid  = *cntl->ControlGuid;

                WmiRegInfo->WmiRegGuid[i].Flags = WMIREG_FLAG_TRACE_CONTROL_GUID | WMIREG_FLAG_TRACED_GUID;
                
                cntl->Level = 0; cntl->Flags[0] = 0;

                WppDebug(0, ("Control GUID::%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                    cntl->ControlGuid->Data1,    cntl->ControlGuid->Data2,    cntl->ControlGuid->Data3, 
                    cntl->ControlGuid->Data4[0], cntl->ControlGuid->Data4[1], cntl->ControlGuid->Data4[2],
                    cntl->ControlGuid->Data4[3], cntl->ControlGuid->Data4[4], cntl->ControlGuid->Data4[5],
                    cntl->ControlGuid->Data4[6], cntl->ControlGuid->Data4[7]
                ));
            }
            Status = STATUS_SUCCESS; *Size = BufferNeeded;
        }
#ifdef WPP_GLOBALLOGGER
        // Check if Global logger is active

        cntl = (PWPP_TRACE_CONTROL_BLOCK) Context;
        for ( ; cntl; cntl = cntl->Next) 
        {
            WppInitGlobalLogger(cntl->ControlGuid,
                (PTRACEHANDLE)&cntl->Logger, &cntl->Flags[0], &cntl->Level
            );
        }
#endif
        break;
    }
    case IRP_MN_ENABLE_EVENTS:
    case IRP_MN_DISABLE_EVENTS:
    {
        if (Context == NULL) { Status = STATUS_WMI_GUID_NOT_FOUND; break; }

        if (BufferLength < sizeof(WNODE_HEADER)) 
        {
            Status = STATUS_INVALID_PARAMETER; break;
        }
        //
        // Initialize locals
        //
        PWNODE_HEADER Wnode = (PWNODE_HEADER)Buffer;

        //
        // Traverse this ProjectControlBlock's ControlBlock list and
        // find the "cntl" ControlBlock which matches the Wnode GUID.
        //
        PWPP_TRACE_CONTROL_BLOCK cntl  = (PWPP_TRACE_CONTROL_BLOCK) Context;
        for (; cntl; cntl = cntl->Next) 
        {
            if (WppIsEqualGuid(cntl->ControlGuid, &Wnode->Guid)) break;
        }
        if (cntl == NULL) { Status = STATUS_WMI_GUID_NOT_FOUND; break; }

        //
        // Do the requested event action
        //
        Status = STATUS_SUCCESS;

        if (MinorFunction == IRP_MN_DISABLE_EVENTS) 
        {
            WppDebug(0, ("WppTraceCallBack: DISABLE_EVENTS\n"));

            cntl->Level = 0; cntl->Flags[0] = 0; cntl->Logger = 0;
        } 
        else {
            TRACEHANDLE lh = (TRACEHANDLE)( Wnode->HistoricalContext );
            cntl->Logger = lh;

            if (WppTraceWinXP == WPPTraceSuite) 
            {
                ULONG ReturnLength; ULONG Level;
                Status = pfnWppQueryTraceInformation(
                    TraceEnableLevelClass, 
                    &Level, sizeof(Level), &ReturnLength, 
                    (PVOID)Wnode
                );
                if (Status == STATUS_SUCCESS) 
                {
                    cntl->Level = (UCHAR)Level;
                }
                Status = pfnWppQueryTraceInformation(
                    TraceEnableFlagsClass,
                    &cntl->Flags[0], sizeof(cntl->Flags[0]), &ReturnLength,
                    (PVOID) Wnode 
                );
            } else {
                cntl->Flags[0] = ((PWPP_TRACE_ENABLE_CONTEXT) &lh)->EnableFlags;
                cntl->Level = (UCHAR) ((PWPP_TRACE_ENABLE_CONTEXT) &lh)->Level;
            }
            WppDebug(0,("WppTraceCallBack: ENABLE_EVENTS "
                         "LoggerId %d, Flags 0x%08X, Level 0x%02X\n",
                (USHORT) cntl->Logger, cntl->Flags[0], cntl->Level
            ));
        }
#ifdef WPP_PRIVATE_ENABLE_CALLBACK
            //
            // Notify changes to flags, level for GUID
            //
            WPP_PRIVATE_ENABLE_CALLBACK(
                cntl->ControlGuid, cntl->Logger,
                (MinorFunction != IRP_MN_DISABLE_EVENTS) ? TRUE:FALSE,
                cntl->Flags[0], cntl->Level
            );
#endif
        break;
    }
    case IRP_MN_ENABLE_COLLECTION       : Status = STATUS_SUCCESS;                  break;
    case IRP_MN_DISABLE_COLLECTION      : Status = STATUS_SUCCESS;                  break;
    case IRP_MN_QUERY_ALL_DATA          : Status = STATUS_INVALID_DEVICE_REQUEST;   break;
    case IRP_MN_QUERY_SINGLE_INSTANCE   : Status = STATUS_INVALID_DEVICE_REQUEST;   break;
    case IRP_MN_CHANGE_SINGLE_INSTANCE  : Status = STATUS_INVALID_DEVICE_REQUEST;   break;
    case IRP_MN_CHANGE_SINGLE_ITEM      : Status = STATUS_INVALID_DEVICE_REQUEST;   break;
    case IRP_MN_EXECUTE_METHOD          : Status = STATUS_INVALID_DEVICE_REQUEST;   break;
    default                             : Status = STATUS_INVALID_DEVICE_REQUEST;   break;
    }

    return Status;
}

extern "C" VOID NTAPI WppClassicProviderCallback(
    _In_ LPCGUID Guid,
    _In_ UCHAR ControlCode,
    _In_ PVOID EnableContext,
    _Inout_ PVOID CallbackContext
    )

/*++

Routine Description:

    Enable callback function when EtwRegisterClassicProvider was used.
    It happens in Windows Vista SP1 and newer.

Arguments:

    Guid - provider guid.

    ControlCode -  code indicating operations request.

    EnableContext - context from the ETW infrastructure.

    CallbackContext - context from the user.

Return Value:

    None.

--*/

{
    UNREFERENCED_PARAMETER (Guid);

    WppDebug(0, ("WppClassicProviderCallback %d\n", (int)ControlCode));

    //
    // Only handle enable and disable operations.
    //

    if ((ControlCode != EVENT_CONTROL_CODE_ENABLE_PROVIDER) &&
        (ControlCode != EVENT_CONTROL_CODE_DISABLE_PROVIDER)) return;

    PWPP_TRACE_CONTROL_BLOCK TraceCb = (PWPP_TRACE_CONTROL_BLOCK)CallbackContext;

    if (ControlCode == EVENT_CONTROL_CODE_DISABLE_PROVIDER) 
    {
        TraceCb->Level = 0; TraceCb->Flags[0] = 0; TraceCb->Logger = 0;
    }
    else {
        PWPP_TRACE_ENABLE_CONTEXT TraceContext = (PWPP_TRACE_ENABLE_CONTEXT)EnableContext;

        TraceCb->Flags[0] = TraceContext->EnableFlags;
        TraceCb->Level = (UCHAR)TraceContext->Level;
        TraceCb->Logger = *((TRACEHANDLE*)TraceContext);

        WppDebug(0, ("ENABLE: LoggerId=%d Flags=%08x Level=%02d\n", 
            (int)TraceContext->LoggerId, TraceCb->Flags[0], TraceCb->Level)
        );
    }
#ifdef WPP_PRIVATE_ENABLE_CALLBACK
    //
    // Notify changes to flags, level for GUID
    //
    WppDebug(0,("WppClassicProviderCallback: calling private callback.\n"));

    WPP_PRIVATE_ENABLE_CALLBACK(
        TraceCb->ControlGuid,TraceCb->Logger, 
        ControlCode, TraceCb->Flags[0], TraceCb->Level
    );
#endif
}

#define WMIREG_FLAG_TRACE_PROVIDER  0x00010000
#define WMIREG_FLAG_CALLBACK        0x80000000 // not exposed in DDK

extern "C" WPPINIT_EXPORT VOID WppInitKm(_In_opt_ PDRIVER_OBJECT DriverObject, _In_opt_ PCUNICODE_STRING RegPath)

/*++

Routine Description:

    This function registers a driver with ETW as a provider of trace
    events from the defined GUIDs.

Arguments:

    DriverObject - Pointer to a driver object. This is required for WppRecorder
                   and is optional otherwise (not used unless it's for
                   WppRecorder).

    RegPath - Optional pointer to registry path, needed for wpp recorder.

Remarks:

   This function is called by the WPP_INIT_TRACING(DriverObject, RegPath) macro.

--*/

{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegPath);

    C_ASSERT(WPP_MAX_FLAG_LEN_CHECK);
    PAGED_CODE();

    if (WPP_CB != WPP_MAIN_CB) WPP_CB = WPP_MAIN_CB;
    else {
        WppDebug(0, ("Warning : WPP_INIT_TRACING already called, ignoring this one")); return;
    }
    PWPP_TRACE_CONTROL_BLOCK WppReg = &WPP_CB[0].Control;

    WppDebug(0, ("WPP Init.\n"));

    if (WppTraceServer08 == WPPTraceSuite) {

        //
        // Windows version >= Vista SP1
        //
        for (; WppReg; WppReg = WppReg->Next) 
        {
            WppReg->RegHandle = 0;
            NTSTATUS Status = pfnEtwRegisterClassicProvider(
                WppReg->ControlGuid, 0,
                WppClassicProviderCallback, (PVOID)WppReg,
                &WppReg->RegHandle
            );
            if (!NT_SUCCESS(Status)) {
                WppDebug(0,("EtwRegisterClassicProvider Status = %d, ControlBlock = %p.\n", Status, WppReg));
            }
        }

    } 
    else if (WppTraceWinXP == WPPTraceSuite) 
    {
        WppReg->Callback = WppTraceCallback;
        NTSTATUS Status = IoWMIRegistrationControl(
            (PDEVICE_OBJECT)WppReg, 
            WMIREG_ACTION_REGISTER  | WMIREG_FLAG_CALLBACK | WMIREG_FLAG_TRACE_PROVIDER
        );
        if (!NT_SUCCESS(Status)) {
            WppDebug(0, ("IoWMIRegistrationControl Status = %08X\n",Status));
        }
    }
}

extern "C" WPPINIT_EXPORT VOID WppCleanupKm(_In_opt_ PDRIVER_OBJECT DriverObject)

/*++

Routine Description:

    This function deregisters a driver from ETW as provider of trace
    events.

Arguments:

    DriverObject - Pointer to a driver object. This is required for WppRecorder
                   and is optional otherwise (not used unless it's for
                   WppRecorder).

Remarks:

    This function is called by the WPP_CLEANUP(DriverObject) macro.

--*/

{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    if (WPP_CB == (WPP_CB_TYPE*)&WPP_CB){
        //
        // WPP_INIT_TRACING macro has not been called
        //
        WppDebug(0, ("Warning : WPP_CLEANUP already called, or called with out WPP_INIT_TRACING first"));
        return;
    }

    if (WppTraceServer08 == WPPTraceSuite) 
    {
        PWPP_TRACE_CONTROL_BLOCK WppReg = &WPP_CB[0].Control;
        for (; WppReg; WppReg = WppReg->Next) 
        {
            if (WppReg->RegHandle) 
            {
                pfnEtwUnregister(WppReg->RegHandle);
                WppDebug(0, ("EtwUnregister RegHandle = %lld.\n",WppReg->RegHandle));
                WppReg->RegHandle = 0;
            } 
            else WppDebug(0, ("WppCleanupKm: invalid RegHandle.\n"));
        }
    } 
    else if (WppTraceWinXP == WPPTraceSuite) 
    {
        PWPP_TRACE_CONTROL_BLOCK WppReg = &WPP_CB[0].Control;
        IoWMIRegistrationControl((PDEVICE_OBJECT)WppReg,
            WMIREG_ACTION_DEREGISTER | WMIREG_FLAG_CALLBACK 
        );
    }
    WPP_CB = (WPP_CB_TYPE*)&WPP_CB;
}


