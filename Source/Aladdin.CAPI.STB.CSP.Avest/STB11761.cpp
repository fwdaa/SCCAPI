#include "stdafx.h"
#include "STB11761.h"

using namespace System::Runtime::InteropServices; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования СТБ 1176.1
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11761::Hash::Construct()
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11761::Hash::Construct); 

	// выделить память для стартового значения
	BYTE arrStart[32]; CRYPT_INTEGER_BLOB blobStart = { 32, arrStart }; 

	// скопировать стартовое значение
	Marshal::Copy(start, 0, IntPtr(arrStart), 32); 

	// создать алгоритм хэширования
	CAPI::CSP::HashHandle hHash = CAPI::CSP::Hash::Construct(); 
	try {
		// установить стартовое значение
		hHash.SetParam(HP_INIT_VECTOR, IntPtr(&blobStart), 0);

		// установить размер хэш-значения
		CAPI::CSP::Handle::SetParam(hHash, HP_BHF_L, 256, 0); 
	}
	// обработать возможную ошибку
	catch(Exception^) { hHash.Destroy(); throw; }  return hHash; 
}
