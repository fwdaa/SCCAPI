#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "..\..\..\RSA\RSAEncoding.h"
#include "RSAPKCS1BSignHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1BSignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения RSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PKCS1::BSignHash::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) 
{$
	// определить требуемый размер буфера
	DWORD cbBlob = Microsoft::RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = Microsoft::RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_RSAFULLPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, 0
	); 
}

array<BYTE>^ Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PKCS1::BSignHash::Sign(
	IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// установить имя алгоритма хэширования 
	BCRYPT_PKCS1_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashAlgorithm->Algorithm->Value) }; 

	// подписать хэш-значение
	return hPrivateKey->SignHash(IntPtr(&info), hash, BCRYPT_PAD_PKCS1);
}
