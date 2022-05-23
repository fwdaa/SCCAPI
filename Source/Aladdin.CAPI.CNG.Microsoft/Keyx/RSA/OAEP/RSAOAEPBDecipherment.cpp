#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAOAEPBDecipherment.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAOAEPBDecipherment.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Ассиметричное шифрование данных RSA OAEP
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Microsoft::Keyx::RSA::OAEP::BDecipherment::Decrypt(
	CAPI::CNG::BKeyHandle^ hPrivateKey, array<BYTE>^ data)
{$
	// определить требуемый размер буфера
	DWORD cbInfo = sizeof(BCRYPT_OAEP_PADDING_INFO) + label->Length; std::vector<BYTE> vecInfo(cbInfo); 

	// выделить буфер требуемого размера
	BCRYPT_OAEP_PADDING_INFO* pInfo = (BCRYPT_OAEP_PADDING_INFO*)&vecInfo[0]; 

	// установить имя алгоритма хэширования 
	pInfo->pszAlgId = PrimitiveProvider::GetHashName(hashOID); 

	// установить имя алгоритма хэширования и указатель на метку
	pInfo->pbLabel = (PBYTE)(pInfo + 1); pInfo->cbLabel = label->Length; 

	// скопировать метку
	Marshal::Copy(label, 0, IntPtr(pInfo->pbLabel), pInfo->cbLabel); 

	// расшифровать данные
	return hPrivateKey->Decrypt(IntPtr(pInfo), data, BCRYPT_PAD_OAEP); 
}

