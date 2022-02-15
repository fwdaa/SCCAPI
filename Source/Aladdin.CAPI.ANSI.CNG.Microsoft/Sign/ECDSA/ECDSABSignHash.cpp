#include "..\..\stdafx.h"
#include "ECDSABSignHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ECDSABSignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения ECDSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Sign::ECDSA::BSignHash::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey)
{$
	// определить требуемый размер буфера
	DWORD cbBlob = X962::Encoding::GetPrivateKeyBlob(algName, (ANSI::X962::IPrivateKey^)privateKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = X962::Encoding::GetPrivateKeyBlob(algName, (ANSI::X962::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_ECCPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, BCRYPT_NO_KEY_VALIDATION
	); 
}

