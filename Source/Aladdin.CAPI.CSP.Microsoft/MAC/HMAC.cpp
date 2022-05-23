#include "..\stdafx.h"
#include "HMAC.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "HMAC.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки HMAC
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ 
Aladdin::CAPI::CSP::Microsoft::MAC::HMAC::Construct(
	CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) 
{$
	// создать алгоритм вычисления имтовставки
	Using<CAPI::CSP::HashHandle^> hHash(CAPI::CSP::Mac::Construct(hContext, hKey)); 

	// указать идентификатор алгоритма хэширования
	HMAC_INFO info = { hashAlgorithm->AlgID, nullptr, 0, nullptr, 0 }; 

	// установить идентификатор алгоритма хэширования
	hHash.Get()->SetParam(HP_HMAC_INFO, IntPtr(&info), 0); return hHash.Detach();
} 
