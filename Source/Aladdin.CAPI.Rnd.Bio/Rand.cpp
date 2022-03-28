#include "stdafx.h"
#include "Rand.h"
#include "Generator.h"

using namespace System::Threading;
using namespace System::Runtime::InteropServices;
using namespace System::Windows::Forms;
 
///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Rand.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Сгенерировать случайные данные
///////////////////////////////////////////////////////////////////////
#pragma unmanaged
static bool GenerateSeed32(HWND hwnd, PBYTE seed, BOOL anyChar, BOOL legacy)
{
	if (anyChar)
	{
		// указать используемый генератор
		AnyChar_GeneratorGUI generator(hwnd, seed, legacy); 
	
		// сгенерировать случайные данные
		return generator.GenerateSeed32() != 0;
	}
	else {
		// указать используемый генератор
		SpecifiedChar_GeneratorGUI generator(hwnd, seed, 10000); 
	
		// сгенерировать случайные данные
		return generator.GenerateSeed32() != 0;
	}
}
#pragma managed

///////////////////////////////////////////////////////////////////////
// Генератор случайных данных (режим совместимости)
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IRand^ Aladdin::CAPI::Rnd::Bio::LegacyRandFactory::CreateRand(Object^ window)
{
	// проверить указание окна
	BYTE buffer[32] = {0}; if (window == nullptr) return nullptr; 
	
	// извлечь описатель окна
	HWND hwnd = (HWND)((IWin32Window^)window)->Handle.ToPointer(); 

	// создать графический диалог
	if (!GenerateSeed32(hwnd, buffer, TRUE, TRUE))
	{
		// выбросить исключение
		throw gcnew OperationCanceledException(); 
	}
	// создать буфер требуемого размера
	array<BYTE>^ seed = gcnew array<BYTE>(32); 

	// скопировать случайные данные
	Marshal::Copy(IntPtr(buffer), seed, 0, seed->Length); 

	// создать генератор случайных данных
	return gcnew GOST::Rnd::TC026_GOSTR3411_2012_512(window, seed); 
}

///////////////////////////////////////////////////////////////////////
// Генератор случайных данных (для сертификации)
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IRand^ Aladdin::CAPI::Rnd::Bio::RandFactory::CreateRand(Object^ window)
{
	// проверить указание окна
	BYTE buffer[32] = {0}; if (window == nullptr) return nullptr; 
	
	// извлечь описатель окна
	HWND hwnd = (HWND)((IWin32Window^)window)->Handle.ToPointer(); 

	// создать графический диалог
	if (!GenerateSeed32(hwnd, buffer, anyChar, FALSE))
	{
		// выбросить исключение
		throw gcnew OperationCanceledException(); 
	}
	// создать буфер требуемого размера
	array<BYTE>^ seed = gcnew array<BYTE>(32); 

	// скопировать случайные данные
	Marshal::Copy(IntPtr(buffer), seed, 0, seed->Length); 

	// создать генератор случайных данных
	return gcnew GOST::Rnd::TC026_GOSTR3411_2012_512(window, seed); 
}
