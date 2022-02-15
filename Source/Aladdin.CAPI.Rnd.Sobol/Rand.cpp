#include "stdafx.h"
#include "Rand.h"

///////////////////////////////////////////////////////////////////////////////
// ƒополнительные определени€ трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Rand.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// √енератор случайных данных
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Rnd::Sobol::RandFactory::RandFactory()
{$
	// загрузить модуль в адресное пространство
	if (sizeof(void*) == 4) hModule = ::LoadLibraryW(L"SnElLock.dll"); 
	
	// загрузить модуль в адресное пространство
	else hModule = ::LoadLibraryW(L"SnElLock64.dll"); 

	// проверить наличие модул€
	AE_CHECK_WINAPI(hModule != nullptr); typedef SNCODE (__stdcall *PFNPRESENT)();
	try {
		// определить адрес функции
		pfnGenerate = (Rand::PFNGENERATE)::GetProcAddress(hModule, "sbGetRand"); 

		// проверить наличие функции
		AE_CHECK_WINAPI(pfnGenerate != nullptr); if (!pfnGenerate) return; 

		// определить адрес функции
		PFNPRESENT pfnPresent = (PFNPRESENT)::GetProcAddress(hModule, "sbisCard"); 

		// проверить наличие функции
		AE_CHECK_WINAPI(pfnPresent != nullptr); if (!pfnPresent) return; 

		// проверить наличие платы
		if ((*pfnPresent)() != SN_OK) AE_CHECK_WINERROR(ERROR_NOT_FOUND);  

		// сгенерировать случайные данные
		BYTE test = 0; SNCODE code = (*pfnGenerate)(&test, 1); 

		// проверить отсутствие ошибок
		if (code != SN_OK) AE_CHECK_WINERROR(ERROR_NOT_FOUND); 
	}
	// выгрузить модуль из адресного пространства
	catch (Exception^) { ::FreeLibrary(hModule); throw; }
}

// выгрузить модуль из адресного пространства
Aladdin::CAPI::Rnd::Sobol::RandFactory::~RandFactory() {$ ::FreeLibrary(hModule); }

void Aladdin::CAPI::Rnd::Sobol::Rand::Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen) 
{$
	// проверить наличие параметров
	if (buffer == nullptr) throw gcnew ArgumentException(); 

	// получить указатель на данные
	pin_ptr<BYTE> ptrBuffer = &buffer[bufferOff]; SNCODE code = SN_OK; 

	// сгенерировать случайные данные
	if (bufferLen > 0) code = (*pfnGenerate)(ptrBuffer, bufferLen); 

	// проверить отсутствие ошибок
	if (code != SN_OK) AE_CHECK_HRESULT(E_FAIL); 
}


