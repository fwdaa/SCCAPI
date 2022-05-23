#include "..\stdafx.h"
#include "X962NPrivateKey.h"
#include "X962Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X962NPrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Личный ключ DH
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Microsoft::X962::NPrivateKey::GetPrivateValue()
{$
	// экспортировать ключ
	array<BYTE>^ blob = Export(nullptr, BCRYPT_ECCPRIVATE_BLOB, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	BCRYPT_ECCKEY_BLOB* pHeader = (BCRYPT_ECCKEY_BLOB*)(PBYTE)ptrBlob; 

	// выделить буфер требуемого размера
	array<BYTE>^ arrX = gcnew array<BYTE>(pHeader->cbKey); 

	// указать начальную позицию для считывания
	DWORD offset = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * pHeader->cbKey; 
		
	// извлечь личный ключ
	Array::Copy(blob, offset, arrX, 0, pHeader->cbKey);

	// раскодировать личный ключ
	d = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 
}

