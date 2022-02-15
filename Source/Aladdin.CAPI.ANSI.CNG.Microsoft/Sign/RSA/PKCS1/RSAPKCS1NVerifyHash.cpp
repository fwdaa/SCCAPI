#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAPKCS1NVerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1NVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения RSA
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::ANSI::CNG::Microsoft::Sign::RSA::PKCS1::NVerifyHash::Verify(
	IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPublicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// установить имя алгоритма хэширования 
	BCRYPT_PKCS1_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashAlgorithm->Algorithm->Value) };  

	// проверить подпись хэш-значения
	hPublicKey->VerifySignature(IntPtr(&info), hash, signature, BCRYPT_PAD_PKCS1);   
}

