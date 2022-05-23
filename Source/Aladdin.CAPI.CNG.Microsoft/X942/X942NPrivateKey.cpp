#include "..\stdafx.h"
#include "X942NPrivateKey.h"
#include "X942Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942NPrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Личный ключ DH
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Microsoft::X942::NPrivateKey::GetPrivateValue()
{$
	// экспортировать ключ
	array<BYTE>^ blob = Export(nullptr, BCRYPT_DH_PRIVATE_BLOB, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	BCRYPT_DH_KEY_BLOB* pHeader = (BCRYPT_DH_KEY_BLOB*)(PBYTE)ptrBlob; 

	// выделить буфер требуемого размера
	array<BYTE>^ arrX = gcnew array<BYTE>(pHeader->cbKey); 

	// указать начальную позицию для считывания
	DWORD offset = sizeof(BCRYPT_DH_KEY_BLOB) + 3 * pHeader->cbKey; 
		
	// извлечь личный ключ
	Array::Copy(blob, offset, arrX,  0, pHeader->cbKey);

	// раскодировать личный ключ
	x = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 
}
