#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAPSSNVerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPSSNVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения RSA PSS
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PSS::NVerifyHash::Verify(
	IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPublicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// установить имя алгоритма хэширования 
	BCRYPT_PSS_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashOID), (UINT)saltLength }; 

	// проверить подпись хэш-значения
	hPublicKey->VerifySignature(IntPtr(&info), hash, signature, BCRYPT_PAD_PSS);   
}
