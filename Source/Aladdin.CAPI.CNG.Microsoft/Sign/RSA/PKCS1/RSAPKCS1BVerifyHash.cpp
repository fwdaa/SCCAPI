#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "..\..\..\RSA\RSAEncoding.h"
#include "RSAPKCS1BVerifyHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1BVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения RSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PKCS1::BVerifyHash::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) 
{$
	// определить требуемый размер буфера
	DWORD cbBlob = Microsoft::RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = Microsoft::RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_RSAPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0
	); 
}

void Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PKCS1::BVerifyHash::Verify(
	IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// установить имя алгоритма хэширования 
	BCRYPT_PKCS1_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashAlgorithm->Algorithm->Value) }; 

	// проверить подпись хэш-значения
	hPublicKey->VerifySignature(IntPtr(&info), hash, signature, BCRYPT_PAD_PKCS1);   
}

