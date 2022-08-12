#include "pch.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dllmain.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����� �����
///////////////////////////////////////////////////////////////////////////////
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, PVOID pReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
	    // ���������������� �����������
        WPP_INIT_TRACING(NULL); break;
    }
    case DLL_PROCESS_DETACH:
    {
	    // ���������� ������� �����������
	    WPP_CLEANUP(); break;
    }}
    return TRUE;
}
