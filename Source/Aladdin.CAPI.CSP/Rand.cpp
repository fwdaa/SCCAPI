#include "stdafx.h"
#include "Rand.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Rand.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Усиленный датчик случайных чисел
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HardwareRand::HardwareRand(
	ContextHandle^ hContext, Object^ window) : Rand(hContext, window)
{ 
	// установить признак использования аппаратного генератора
	try { hContext->SetLong(PP_USE_HARDWARE_RNG, 0, 0); } catch (Exception^) {}
}

void Aladdin::CAPI::CSP::HardwareRand::Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen)
{$
	// при указании родительского окна
	HWND hwnd = NULL; if (Window != nullptr)
	{
		// извлечь описатель окна
		hwnd = (HWND)((IWin32Window^)Window)->Handle.ToPointer(); 
	}
	// установить активное окно
	Handle->SetParam(PP_CLIENT_HWND, IntPtr(&hwnd), 0); 
	try { 
		// сгенерировать случайные данные
		hwnd = NULL; Rand::Generate(buffer, bufferOff, bufferLen); 
	}
	// сбросить активное окно
	finally { Handle->SetParam(PP_CLIENT_HWND, IntPtr(&hwnd), 0); }
}
