#include "stdafx.h"
#include "Rand.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Rand.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Rnd::Accord::RandFactory::RandFactory()
{$
	// загрузить модуль в адресное пространство
	if (sizeof(void*) == 4) hModule = ::LoadLibraryW(L"tmdrv32.dll"); 
	
	// загрузить модуль в адресное пространство
	else hModule = ::LoadLibraryW(L"tmdrv64.dll"); 

	// проверить наличие модуля
	AE_CHECK_WINAPI(hModule != nullptr); typedef DWORD (*PFNPRESENT)();
	try {
		// определить адрес функции
		pfnGenerate = (Rand::PFNGENERATE)::GetProcAddress(hModule, "TmGetRandomBytes"); 

		// проверить наличие функции
		AE_CHECK_WINAPI(pfnGenerate != nullptr); if (!pfnGenerate) return; 

		// определить адрес функции
		PFNPRESENT pfnPresent = (PFNPRESENT)::GetProcAddress(hModule, "TmDriverPresent"); 

		// проверить наличие функции
		AE_CHECK_WINAPI(pfnPresent != nullptr); if (!pfnPresent) return; 

		// проверить наличие платы
		if (!(*pfnPresent)()) AE_CHECK_WINERROR(ERROR_NOT_FOUND);  

		// сгенерировать случайные данные
		BYTE test = 0; DWORD code = (*pfnGenerate)(&test, 1); 

		// проверить отсутствие ошибок
		if (code != 0) AE_CHECK_WINERROR(ERROR_NOT_FOUND); 
	}
	// выгрузить модуль из адресного пространства
	catch (Exception^) { ::FreeLibrary(hModule); throw; }
}

// выгрузить модуль из адресного пространства
Aladdin::CAPI::Rnd::Accord::RandFactory::~RandFactory() {$ ::FreeLibrary(hModule); }

void Aladdin::CAPI::Rnd::Accord::Rand::Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen) 
{$
	// проверить наличие параметров
	if (buffer == nullptr) throw gcnew ArgumentException(); 

	// получить указатель на данные
	pin_ptr<BYTE> ptrBuffer = &buffer[bufferOff]; int blockSize = 60; DWORD code = 0; 

	// для всех целых частей 
	for (; bufferLen > blockSize; bufferLen -= blockSize, ptrBuffer += blockSize)
	{
		// сгенерировать случайные данные
		code = (*pfnGenerate)(ptrBuffer, blockSize); 

		// проверить отсутствие ошибок
		if (code != 0) AE_CHECK_HRESULT(E_FAIL); 
	}
	// сгенерировать случайные данные
	if (bufferLen > 0) code = (*pfnGenerate)(ptrBuffer, bufferLen); 

	// проверить отсутствие ошибок
	if (code != 0) AE_CHECK_HRESULT(E_FAIL); 
}
