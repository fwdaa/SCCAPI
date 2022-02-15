#include "..\..\..\stdafx.h"
#include "..\..\..\RSA\RSAEncoding.h"
#include "RSAPKCS1BEncipherment.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1BEncipherment.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Ассиметричное шифрование данных RSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::RSA::PKCS1::BEncipherment::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, IPublicKey^ publicKey) 
{$
	// определить требуемый размер буфера
	DWORD cbBlob = Microsoft::RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = Microsoft::RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, BCRYPT_RSAPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0); 
}

