#include "StdAfx.h"
#include "Aladdin.CAPI.OpenSSL.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dllmain.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����� ����� � DLL
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PVOID)
{
    // ���������������� �����������
    if (dwReason == DLL_PROCESS_ATTACH) { WPP_INIT_TRACING(NULL); }

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{$
        // ���������� ������ �������� ��� �������������
		DisableThreadLibraryCalls(hModule); 
		
		// ��������� �������������
		Aladdin::CAPI::OpenSSL::Init(hModule); break; 
	}
	case DLL_PROCESS_DETACH:
	{$
		// ���������� ���������� �������
		Aladdin::CAPI::OpenSSL::Done(); break; 
	}}
	// ���������� ������� �����������
	if (dwReason == DLL_PROCESS_DETACH) WPP_CLEANUP();

	return TRUE; 
}
#else

__attribute__((constructor)) static void ProcessAttach() 
{ 
	// ��������� �������������
	WPP_INIT_TRACING(NULL); Aladdin::CAPI::OpenSSL::Init();
}
// ���������� ���������� �������
__attribute__((destructor)) static void ProcessDetach() 
{ 
	// ���������� ���������� �������
	Aladdin::CAPI::OpenSSL::Done(); WPP_CLEANUP();
}

#endif
