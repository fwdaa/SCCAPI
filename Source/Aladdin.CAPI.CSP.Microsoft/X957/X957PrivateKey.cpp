#include "..\stdafx.h"
#include "X957PrivateKey.h"

///////////////////////////////////////////////////////////////////////////////
// ƒополнительные определени€ трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957PrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Ћичный ключ DSA
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Microsoft::X957::PrivateKey::GetPrivateValue()
{$
    // экспортировать личный ключ
    array<BYTE>^ blob = Export(nullptr, CRYPT_BLOB_VER3); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob;

	// выполнить преобразование типа
	DSSPRIVKEY_VER3* pInfo = (DSSPRIVKEY_VER3*)(pBlob + 1); 

	// определить смещение параметров
	DWORD offsetParams = sizeof(PUBLICKEYSTRUC) + sizeof(DSSPRIVKEY_VER3); 
	
    // определить размеры чисел
    DWORD cbP = pInfo->bitlenP / 8; DWORD cbQ = pInfo->bitlenQ / 8; 
	DWORD cbX = pInfo->bitlenX / 8; DWORD cbJ = pInfo->bitlenJ / 8;
	
	// выделить буфер требуемого размера
	array<BYTE>^ arrX = gcnew array<BYTE>(cbX); 

	// скопировать значение личного ключа
	Array::Copy(blob, offsetParams + 3 * cbP + cbQ + cbJ, arrX, 0, cbX); 

	// раскодировать значение
	x = Math::Convert::ToBigInteger(arrX, Endian); 
}

