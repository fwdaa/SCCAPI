#include "..\stdafx.h"
#include "X957NPrivateKey.h"
#include "X957Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957NPrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Личный ключ DH
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Microsoft::X957::NPrivateKey::GetPrivateValue()
{$
	// экспортировать ключ
	array<BYTE>^ blob = Export(nullptr, BCRYPT_DSA_PRIVATE_BLOB, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	BCRYPT_DSA_KEY_BLOB* pHeader = (BCRYPT_DSA_KEY_BLOB*)(PBYTE)ptrBlob; 

	// определить смещение ключа
	DWORD offsetKey = sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * pHeader->cbKey; 
		
	// извлечь личный ключ
	array<BYTE>^ arrX = gcnew array<BYTE>(20); Array::Copy(blob, offsetKey, arrX, 0, 20);

	// раскодировать личный ключ
	x = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 
}
