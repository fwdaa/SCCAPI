#include "stdafx.h"
#include "Rand.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Rand.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ��������� ������ ��������� �����
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HardwareRand::HardwareRand(
	ContextHandle^ hContext, Object^ window) : Rand(hContext, window)
{ 
	// ���������� ������� ������������� ����������� ����������
	try { hContext->SetLong(PP_USE_HARDWARE_RNG, 0, 0); } catch (Exception^) {}
}

void Aladdin::CAPI::CSP::HardwareRand::Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen)
{$
	// ��� �������� ������������� ����
	HWND hwnd = NULL; if (Window != nullptr)
	{
		// ������� ��������� ����
		hwnd = (HWND)((IWin32Window^)Window)->Handle.ToPointer(); 
	}
	// ���������� �������� ����
	Handle->SetParam(PP_CLIENT_HWND, IntPtr(&hwnd), 0); 
	try { 
		// ������������� ��������� ������
		hwnd = NULL; Rand::Generate(buffer, bufferOff, bufferLen); 
	}
	// �������� �������� ����
	finally { Handle->SetParam(PP_CLIENT_HWND, IntPtr(&hwnd), 0); }
}
