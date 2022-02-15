#include "stdafx.h"
#include "Generator.h"

//////////////////////////////////////////////////////////////////////////
// Отобразить диалог генерации
//////////////////////////////////////////////////////////////////////////
#ifdef CERT_TEST
BOOL ShowGeneratorDialog(GeneratorGUI* pGenerator, HMODULE, LPCDLGTEMPLATEW, HWND, DLGPROC)
{
	static int entry = 0; entry++; HCRYPTPROV hProv = NULL; 

	// инициализировать переменные
	long long timer = pGenerator->GetMiсrosecondsSinceEpoch() + entry * 1000000LL * 64; 
	
	// открыть провайдер для генерации случайных символов
	::CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT); 
	
	// имитировать события нажатия клавиши
	for (ULONG value = 0; pGenerator->OnValidChar(timer, 0) < 100; value = 0) 
	{
		// сгенерировать случайные данные
		::CryptGenRandom(hProv, sizeof(value), (PBYTE)&value); 

		// вычислить новое время
		timer += 500000LL + value % (1024 * 1024); 
	}
	// закрыть описатель провайдера
	::CryptReleaseContext(hProv, 0); return TRUE; 
}
#endif 
