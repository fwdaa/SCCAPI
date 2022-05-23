#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAPSSNSignHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPSSNSignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения RSA PSS
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PSS::NSignHash::Sign(
	SecurityObject^ scope, IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPrivateKey,  
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// установить имя алгоритма хэширования 
	BCRYPT_PSS_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashOID), (UINT)saltLength }; 

	// подписать хэш-значение
	return Sign(scope, hPrivateKey, IntPtr(&info), hash, BCRYPT_PAD_PSS);
}
