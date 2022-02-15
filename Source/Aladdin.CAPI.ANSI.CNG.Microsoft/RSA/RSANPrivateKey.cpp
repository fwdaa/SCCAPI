#include "..\stdafx.h"
#include "RSANPrivateKey.h"
#include "RSAEncoding.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSANPrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Личный ключ RSA
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::ANSI::CNG::Microsoft::RSA::NPrivateKey::GetPrivateValue()
{$
	// экспортировать ключ
	array<BYTE>^ blob = Export(nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	BCRYPT_RSAKEY_BLOB* pHeader = (BCRYPT_RSAKEY_BLOB*)(PBYTE)ptrBlob; 

	// выделить буферы требуемых размеров
	array<BYTE>^ arrPubExp  = gcnew array<BYTE>(pHeader->cbPublicExp); 
	array<BYTE>^ arrModulus = gcnew array<BYTE>(pHeader->cbModulus	); 
	array<BYTE>^ arrPrime1  = gcnew array<BYTE>(pHeader->cbPrime1	); 
	array<BYTE>^ arrPrime2  = gcnew array<BYTE>(pHeader->cbPrime2	); 
	array<BYTE>^ arrExp1	= gcnew array<BYTE>(pHeader->cbPrime1	); 
	array<BYTE>^ arrExp2	= gcnew array<BYTE>(pHeader->cbPrime2	); 
	array<BYTE>^ arrCoeff   = gcnew array<BYTE>(pHeader->cbPrime1	); 
	array<BYTE>^ arrPrivExp = gcnew array<BYTE>(pHeader->cbModulus	); 

	// указать смещение параметров
	DWORD offset = sizeof(BCRYPT_RSAKEY_BLOB); 

	// извлечь отдельные элементы
	Array::Copy(blob, offset, arrPubExp,  0, pHeader->cbPublicExp); offset += pHeader->cbPublicExp;  
	Array::Copy(blob, offset, arrModulus, 0, pHeader->cbModulus	 ); offset += pHeader->cbModulus;  
	Array::Copy(blob, offset, arrPrime1,  0, pHeader->cbPrime1	 ); offset += pHeader->cbPrime1;  
	Array::Copy(blob, offset, arrPrime2,  0, pHeader->cbPrime2	 ); offset += pHeader->cbPrime2;  
	Array::Copy(blob, offset, arrExp1,    0, pHeader->cbPrime1	 ); offset += pHeader->cbPrime1;  
	Array::Copy(blob, offset, arrExp2,    0, pHeader->cbPrime2	 ); offset += pHeader->cbPrime2;  
	Array::Copy(blob, offset, arrCoeff,   0, pHeader->cbPrime1	 ); offset += pHeader->cbPrime1;  
	Array::Copy(blob, offset, arrPrivExp, 0, pHeader->cbModulus	 ); offset += pHeader->cbModulus; 

	// раскодировать отдельные элементы
	publicExponent  = Math::Convert::ToBigInteger(arrPubExp , Encoding::Endian); 
	modulus         = Math::Convert::ToBigInteger(arrModulus, Encoding::Endian); 
	prime1          = Math::Convert::ToBigInteger(arrPrime1 , Encoding::Endian); 
	prime2          = Math::Convert::ToBigInteger(arrPrime2 , Encoding::Endian); 
	exponent1	    = Math::Convert::ToBigInteger(arrExp1   , Encoding::Endian); 
	exponent2	    = Math::Convert::ToBigInteger(arrExp2   , Encoding::Endian); 
	coefficient     = Math::Convert::ToBigInteger(arrCoeff  , Encoding::Endian); 
	privateExponent = Math::Convert::ToBigInteger(arrPrivExp, Encoding::Endian); 
}
