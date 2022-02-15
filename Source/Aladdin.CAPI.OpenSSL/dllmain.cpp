#include "pch.h"
#include "Aladdin.CAPI.OpenSSL.h"
#include "wxwidgets.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dllmain.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Точка входа
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
void Aladdin::CAPI::OpenSSL::Init(HMODULE hModule)
{$ 
    // инициализировать WxWidgets
    WxDllEntryStartup<Aladdin::CAPI::OpenSSL::WxWidgets::WxDllApp>(hModule);
}
#else 
void Aladdin::CAPI::OpenSSL::Init()
{$ 
    // инициализировать WxWidgets
    WxDllEntryStartup<Aladdin::CAPI::OpenSSL::WxWidgets::WxDllApp>();
}
#endif 

// освободить выделенные ресурсы
void Aladdin::CAPI::OpenSSL::Done()
{$ 
    // освободить выделенные ресурсы
    WxDllEntryCleanup(); 
}
