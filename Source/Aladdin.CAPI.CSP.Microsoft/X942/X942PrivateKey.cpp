#include "..\stdafx.h"
#include "X942PrivateKey.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942PrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Личный ключ DH
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Microsoft::X942::PrivateKey::GetPrivateValue()
{$
    // экспортировать личный ключ
    array<BYTE>^ blob = Export(nullptr, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob;

	// получить информацию об экспоненте и модуле
	DSSPUBKEY* pInfo = (DSSPUBKEY*)(pBlob + 1); 
	
	// определить смещение параметров
	DWORD offsetParams = sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY); 
	
	// выделить буфер требуемого размера
	DWORD cbX = pInfo->bitlen / 8; array<BYTE>^ arrX = gcnew array<BYTE>(cbX);

	// скопировать значение личного ключа
	Array::Copy(blob, offsetParams + 2 * cbX, arrX, 0, cbX); 

	// раскодировать значение
	x = Math::Convert::ToBigInteger(arrX, Endian); 
}

