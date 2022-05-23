#include "..\..\stdafx.h"
#include "DSABSignHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSABSignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения DSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Sign::DSA::BSignHash::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey)
{$
	// определить требуемый размер буфера
	DWORD cbBlob = X957::Encoding::GetPrivateKeyBlob((ANSI::X957::IPrivateKey^)privateKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DSA_KEY_BLOB* pbBlob = (BCRYPT_DSA_KEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = X957::Encoding::GetPrivateKeyBlob((ANSI::X957::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_DSA_PRIVATE_BLOB, IntPtr(pbBlob), cbBlob, BCRYPT_NO_KEY_VALIDATION
	); 
}

