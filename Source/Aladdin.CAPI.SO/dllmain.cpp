#include "StdAfx.h"
#include "Aladdin.CAPI.OpenSSL.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dllmain.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Точка входа в DLL
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PVOID)
{
    // инициализировать трассировку
    if (dwReason == DLL_PROCESS_ATTACH) { WPP_INIT_TRACING(NULL); }

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{$
        // установить модуль ресурсов для использования
		DisableThreadLibraryCalls(hModule); 
		
		// выполнить инициализацию
		Aladdin::CAPI::OpenSSL::Init(hModule); break; 
	}
	case DLL_PROCESS_DETACH:
	{$
		// освободить выделенные ресурсы
		Aladdin::CAPI::OpenSSL::Done(); break; 
	}}
	// освободить ресурсы трассировки
	if (dwReason == DLL_PROCESS_DETACH) WPP_CLEANUP();

	return TRUE; 
}
#else

__attribute__((constructor)) static void ProcessAttach() 
{ 
	// выполнить инициализацию
	WPP_INIT_TRACING(NULL); Aladdin::CAPI::OpenSSL::Init();
}
// освободить выделенные ресурсы
__attribute__((destructor)) static void ProcessDetach() 
{ 
	// освободить выделенные ресурсы
	Aladdin::CAPI::OpenSSL::Done(); WPP_CLEANUP();
}

#endif
