#include "..\..\stdafx.h"
#include "ECDSABVerifyHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ECDSABVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения ECDSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Sign::ECDSA::BVerifyHash::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) 
{$
	// определить требуемый размер буфера
	DWORD cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, BCRYPT_ECCPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0); 
}

