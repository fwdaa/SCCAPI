#include "..\stdafx.h"
#include "RSAPrivateKey.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Личный ключ RSA
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Microsoft::RSA::PrivateKey::GetPrivateValue()
{$
    // экспортировать личный ключ
    array<BYTE>^ blob = Export(nullptr, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; RSAPUBKEY* pInfo = (RSAPUBKEY*)(pBlob + 1); 

	// определить смещение параметров
	DWORD offsetParams = sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY); DWORD offset = 0; 

    // выделить буферы требуемого размера    
    DWORD cbModulus     = pInfo->bitlen /  8; array<BYTE>^ arrModulus     = gcnew array<BYTE>(cbModulus    ); 
    DWORD cbPrime1      = pInfo->bitlen / 16; array<BYTE>^ arrPrime1      = gcnew array<BYTE>(cbPrime1     ); 
    DWORD cbPrime2      = pInfo->bitlen / 16; array<BYTE>^ arrPrime2      = gcnew array<BYTE>(cbPrime2     ); 
    DWORD cbExponent1   = pInfo->bitlen / 16; array<BYTE>^ arrExponent1   = gcnew array<BYTE>(cbExponent1  ); 
    DWORD cbExponent2   = pInfo->bitlen / 16; array<BYTE>^ arrExponent2   = gcnew array<BYTE>(cbExponent2  ); 
    DWORD cbCoefficient = pInfo->bitlen / 16; array<BYTE>^ arrCoefficient = gcnew array<BYTE>(cbCoefficient); 
    DWORD cbPrivate     = pInfo->bitlen /  8; array<BYTE>^ arrPrivate     = gcnew array<BYTE>(cbPrivate    ); 

    // извлечь значения параметров
    Array::Copy(blob, offsetParams + offset, arrModulus    , 0, cbModulus    ); offset += cbModulus    ; 
    Array::Copy(blob, offsetParams + offset, arrPrime1     , 0, cbPrime1     ); offset += cbPrime1     ; 
    Array::Copy(blob, offsetParams + offset, arrPrime2     , 0, cbPrime2     ); offset += cbPrime2     ; 
    Array::Copy(blob, offsetParams + offset, arrExponent1  , 0, cbExponent1  ); offset += cbExponent1  ; 
    Array::Copy(blob, offsetParams + offset, arrExponent2  , 0, cbExponent2  ); offset += cbExponent2  ; 
    Array::Copy(blob, offsetParams + offset, arrCoefficient, 0, cbCoefficient); offset += cbCoefficient; 
    Array::Copy(blob, offsetParams + offset, arrPrivate    , 0, cbPrivate    ); offset += cbPrivate    ; 

	// раскодировать значения
	modulus         = Math::Convert::ToBigInteger(arrModulus    , Endian); 
	prime1          = Math::Convert::ToBigInteger(arrPrime1     , Endian); 
	prime2          = Math::Convert::ToBigInteger(arrPrime2     , Endian); 
	exponent1       = Math::Convert::ToBigInteger(arrExponent1  , Endian); 
	exponent2       = Math::Convert::ToBigInteger(arrExponent2  , Endian); 
	coefficient     = Math::Convert::ToBigInteger(arrCoefficient, Endian); 
	privateExponent = Math::Convert::ToBigInteger(arrPrivate    , Endian); 

    // установить значение открытой экспоненты
    publicExponent = Math::BigInteger::ValueOf(pInfo->pubexp); 
}


