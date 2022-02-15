// ѕри обработке исходного файла утилитой “raceWpp создаетс€ TMH-файл, 
// содержащий дополнительные определени€, требуемые дл€ трассировки. —реди 
// указанных определений будут следующие (на основе приведенного значени€
// WPP_CONTROL_GUIDS): 
// 
#include <windows.h>                    // определени€ Windows
#include <wmistr.h>                     // определени€ WMI
#include <evntrace.h>                   // определени€ ETW
#include <TraceETW.h>

// назначение провайдерам пор€дковых номеров 
enum WPP_CTL_NAMES { WPP_CTL_Regular, WPP_CTL_HiFreq, WPP_LAST_CTL };
 
// C-определени€ GUID провайдеров
extern __declspec(selectany) const GUID WPP_ThisDir_CTLGUID_Regular = {
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
extern __declspec(selectany) const GUID WPP_ThisDir_CTLGUID_HiFreq = {
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
// назначение уникальных номеров всем категори€м сообщений провайдеров
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
// // дл€ дальнейшей проверки максмально допустимого числа категорий провайдера
#define MAX_NUMBER_OF_ETW_FLAGS 34 // 32 flags plus 2 separators
enum _WPP_FLAG_LEN_ENUM_MAX { WPP_MAX_FLAG_LEN_CHECK = (1  
     && ((WPP_BLOCK_END_Regular & 0xFFFF) < MAX_NUMBER_OF_ETW_FLAGS) 
     && ((WPP_BLOCK_END_HiFreq  & 0xFFFF) < MAX_NUMBER_OF_ETW_FLAGS) 
)};
// 
// номер 32-разр€дного слова дл€ бита категории
// #define WPP_FLAG_NO(CTL) ((0xFFFF & ((CTL)-1)) / 32)
// 
// маска позиции бита категории в 32-разр€дном слове
// #define WPP_MASK(CTL)    (1 << (((CTL)-1) & 31))
// 
// 
enum {
    WPP_VER_WIN2K_CB_FORWARD_PTR      = 0x01,
    WPP_VER_WHISTLER_CB_FORWARD_PTR   = 0x02,
    WPP_VER_LH_CB_FORWARD_PTR         = 0x03
};
typedef struct _WPP_WIN2K_CONTROL_BLOCK {
    TRACEHANDLE Logger;
    ULONG Flags;
    ULONG Level;
    LPCGUID ControlGuid;
} WPP_WIN2K_CONTROL_BLOCK, *PWPP_WIN2K_CONTROL_BLOCK;

#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct _WPP_TRACE_CONTROL_BLOCK {
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
} WPP_TRACE_CONTROL_BLOCK, *PWPP_TRACE_CONTROL_BLOCK;
#pragma warning(pop)
 
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
 
#ifndef WPP_REGISTER_TRACE_GUIDS
#define WPP_REGISTER_TRACE_GUIDS  RegisterTraceGuids
#endif
#ifndef WPP_UNREGISTER_TRACE_GUIDS
#define WPP_UNREGISTER_TRACE_GUIDS  UnregisterTraceGuids
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
#ifndef WPP_TRACE
#define WPP_TRACE TraceMessage
#endif


// 
// #define WPP_CTRL_NO(CTL) ((CTL) >> 16)
// #define WPP_CONTROL(CTL) (WPP_CB[WPP_CTRL_NO(CTL)].Control)
//
///////////////////////////////////////////////////////////////////////////////////
LPCGUID WPP_REGISTRATION_GUIDS[WPP_LAST_CTL];
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

// массив GUID провайдеров и функци€ его заполнени€
__inline void WPP_INIT_GUID_ARRAY(LPCGUID* Arr) {
     *Arr++ = &WPP_ThisDir_CTLGUID_Regular; 
     *Arr++ = &WPP_ThisDir_CTLGUID_HiFreq; 
}
__inline void WPP_INIT_CONTROL_ARRAY(WPP_CB_TYPE* Arr) 
{
     Arr->Control.Ptr = NULL;
     Arr->Control.Next = ((WPP_TRACE_CONTROL_BLOCK*)(
         WPP_CTL_Regular + 1 == WPP_LAST_CTL ? 0 : WPP_MAIN_CB + WPP_CTL_Regular + 1
     )); 
     Arr->Control.FlagsLen = WPP_FLAG_LEN;
     Arr->Control.Level = 0;
     Arr->Control.Options = 0;
     Arr->Control.Flags[0] = 0;
     ++Arr; 
     Arr->Control.Ptr = NULL;
     Arr->Control.Next = ((WPP_TRACE_CONTROL_BLOCK*)(
         WPP_CTL_HiFreq + 1 == WPP_LAST_CTL ? 0 : WPP_MAIN_CB + WPP_CTL_HiFreq + 1
     ));
     Arr->Control.FlagsLen = WPP_FLAG_LEN;
     Arr->Control.Level = 0;
     Arr->Control.Options = 0;
     Arr->Control.Flags[0] = 0;
     ++Arr; 
}
#define WppLoadTracingSupport
#define WPP_INIT_STATIC_DATA WPP_INIT_CONTROL_ARRAY(WPP_MAIN_CB)

#ifndef WppDebug
#define WppDebug(a,b)
#endif

#define WPP_INIT_TRACING(AppName)                               \
      WppLoadTracingSupport;                                    \
      (WPP_CONTROL_ANNOTATION(),WPP_INIT_STATIC_DATA,           \
      WPP_INIT_GUID_ARRAY((LPCGUID*)&WPP_REGISTRATION_GUIDS),   \
      WPP_CB= WPP_MAIN_CB,                                      \
      WppInitUm(AppName))

ULONG __stdcall WppControlCallback(
    IN WMIDPREQUESTCODE RequestCode,
    IN PVOID Context,
    _Inout_ ULONG *InOutBufferSize,
    _Inout_ PVOID Buffer
    )
{
    PWPP_TRACE_CONTROL_BLOCK Ctx = (PWPP_TRACE_CONTROL_BLOCK)Context;
    TRACEHANDLE Logger;
    UCHAR Level;
    DWORD Flags;

    *InOutBufferSize = 0;

    switch (RequestCode)
    {
        case WMI_ENABLE_EVENTS:
        {
            Logger = WPP_GET_TRACE_LOGGER_HANDLE( Buffer );
            Level = WPP_GET_TRACE_ENABLE_LEVEL(Logger);
            Flags = WPP_GET_TRACE_ENABLE_FLAGS(Logger);

            WppDebug(1, ("[WppInit] WMI_ENABLE_EVENTS Ctx %p Flags %x"
                     " Lev %d Logger %I64x\n",
                     Ctx, Flags, Level, Logger) );
            break;
        }

        case WMI_DISABLE_EVENTS:
        {
            Logger = 0;
            Flags  = 0;
            Level  = 0;
            WppDebug(1, ("[WppInit] WMI_DISABLE_EVENTS Ctx 0x%08p\n", Ctx));
            break;
        }
        default:
        {
            return ERROR_INVALID_PARAMETER;
        }
    }

    if (Ctx->Options & WPP_VER_WHISTLER_CB_FORWARD_PTR && Ctx->Cb) {
        Ctx = Ctx->Cb; // use forwarding address
    }

    Ctx->Logger   = Logger;
    Ctx->Level    = Level;
    Ctx->Flags[0] = Flags;

#ifdef WPP_PRIVATE_ENABLE_CALLBACK
    WPP_PRIVATE_ENABLE_CALLBACK(Ctx->ControlGuid,
                                Logger,
                                (RequestCode != WMI_DISABLE_EVENTS) ? TRUE : FALSE,
                                Flags,
                                Level);
#endif

    return(ERROR_SUCCESS);
}

VOID WppInitUm(_In_opt_ LPCWSTR)
{
    C_ASSERT(WPP_MAX_FLAG_LEN_CHECK);

    ULONG Status = ERROR_SUCCESS; 

    LPCGUID* RegistrationGuids = (LPCGUID *)&WPP_REGISTRATION_GUIDS;


    WppDebug(1, ("Registering %ws\n", AppName) );

    // дл€ всех про
    for (PWPP_TRACE_CONTROL_BLOCK Control = &WPP_CB[0].Control; Control; Control = Control->Next) 
    {
        LPCGUID ControlGuid = *RegistrationGuids++;

        TRACE_GUID_REGISTRATION TraceRegistration;
        TraceRegistration.Guid = ControlGuid;
        TraceRegistration.RegHandle = 0;
        Control->ControlGuid = ControlGuid;

        WppDebug(1, ("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x %ws : %d\n",
            ControlGuid->Data1,    ControlGuid->Data2,    ControlGuid->Data3,
            ControlGuid->Data4[0], ControlGuid->Data4[1], ControlGuid->Data4[2], ControlGuid->Data4[3],
            ControlGuid->Data4[4], ControlGuid->Data4[5], ControlGuid->Data4[6], ControlGuid->Data4[7], 
            AppName, Control->FlagsLen
         )); 
        Status = WPP_REGISTER_TRACE_GUIDS(
            WppControlCallback, Control, ControlGuid, 1, &TraceRegistration, 0, 0, 
            &Control->UmRegistrationHandle
        );
        if (Status != ERROR_SUCCESS) 
        {
            WppDebug(1, ("RegisterTraceGuid failed %d\n", Status));
        }
    }
}

VOID WppCleanupUm()
{
    if (WPP_CB == (WPP_CB_TYPE*)&WPP_CB) return; 

    WppDebug(1, ("Cleanup\n") );

    for (PWPP_TRACE_CONTROL_BLOCK Control = &WPP_CB[0].Control; Control; Control = Control->Next) 
    {
        WppDebug(1, ("UnRegistering %I64x\n", Control->UmRegistrationHandle));

        if (Control->UmRegistrationHandle) 
        {
            WPP_UNREGISTER_TRACE_GUIDS(Control->UmRegistrationHandle);

            Control->UmRegistrationHandle = (TRACEHANDLE)NULL ;
        }
    }
    WPP_CB = (WPP_CB_TYPE*)&WPP_CB;
}

