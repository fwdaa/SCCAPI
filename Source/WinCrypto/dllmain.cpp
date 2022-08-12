#include "pch.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dllmain.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Точка входа
///////////////////////////////////////////////////////////////////////////////
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, PVOID pReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
	    // инициализировать трассировку
        WPP_INIT_TRACING(NULL); break;
    }
    case DLL_PROCESS_DETACH:
    {
	    // освободить ресурсы трассировки
	    WPP_CLEANUP(); break;
    }}
    return TRUE;
}
