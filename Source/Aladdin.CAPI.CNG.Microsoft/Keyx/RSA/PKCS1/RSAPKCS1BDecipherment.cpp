#include "..\..\..\stdafx.h"
#include "..\..\..\RSA\RSAEncoding.h"
#include "RSAPKCS1BDecipherment.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1BDecipherment.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Ассиметричное шифрование данных RSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Keyx::RSA::PKCS1::BDecipherment::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, IPrivateKey^ privateKey) 
{$
	// определить требуемый размер буфера
	DWORD cbBlob = Microsoft::RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = Microsoft::RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, 0); 
}

