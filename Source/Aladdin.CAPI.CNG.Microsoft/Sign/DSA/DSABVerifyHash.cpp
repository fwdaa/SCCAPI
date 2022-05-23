#include "..\..\stdafx.h"
#include "DSABVerifyHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSABVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Подпись хэш-значения DSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Sign::DSA::BVerifyHash::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey)
{$
	// определить требуемый размер буфера
	DWORD cbBlob = X957::Encoding::GetPublicKeyBlob((ANSI::X957::IPublicKey^)publicKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DSA_KEY_BLOB* pbBlob = (BCRYPT_DSA_KEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = X957::Encoding::GetPublicKeyBlob((ANSI::X957::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_DSA_PUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0
	); 
}
