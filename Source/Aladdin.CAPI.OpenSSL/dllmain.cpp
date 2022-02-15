#include "pch.h"
#include "Aladdin.CAPI.OpenSSL.h"
#include "wxwidgets.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dllmain.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����� �����
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
void Aladdin::CAPI::OpenSSL::Init(HMODULE hModule)
{$ 
    // ���������������� WxWidgets
    WxDllEntryStartup<Aladdin::CAPI::OpenSSL::WxWidgets::WxDllApp>(hModule);
}
#else 
void Aladdin::CAPI::OpenSSL::Init()
{$ 
    // ���������������� WxWidgets
    WxDllEntryStartup<Aladdin::CAPI::OpenSSL::WxWidgets::WxDllApp>();
}
#endif 

// ���������� ���������� �������
void Aladdin::CAPI::OpenSSL::Done()
{$ 
    // ���������� ���������� �������
    WxDllEntryCleanup(); 
}
