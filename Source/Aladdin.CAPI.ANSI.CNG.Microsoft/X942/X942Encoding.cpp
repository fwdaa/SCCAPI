#include "..\stdafx.h"
#include "X942Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942Encoding.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Преобразовать формат открытого ключа
///////////////////////////////////////////////////////////////////////////
Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetPublicKeyInfo(
	CAPI::CNG::NKeyHandle^ hPublicKey)
{$
	// определить требуемый размер буфера
	DWORD cbBlob = hPublicKey->Export(nullptr, LEGACY_DH_PUBLIC_BLOB, 0, IntPtr::Zero, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 
	
	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 

	// экспортировать открытый ключ
	cbBlob = hPublicKey->Export(nullptr, LEGACY_DH_PUBLIC_BLOB, 0, IntPtr(pBlob), cbBlob); 

	// указать способ кодирования чисел
	Math::Endian endian = Math::Endian::LittleEndian; 

	// преобразовать тип указателя
	DHPUBKEY_VER3* pInfo = (DHPUBKEY_VER3*)(pBlob + 1); 

	// определить смещение параметров
	DWORD offset = sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY_VER3); 

	// выделить память для параметров
	array<BYTE>^ arrP = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 
	array<BYTE>^ arrQ = gcnew array<BYTE>((pInfo->bitlenQ + 7) / 8); 
	array<BYTE>^ arrG = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 
	array<BYTE>^ arrY = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 

	// прочитать параметры
	Array::Copy(blob, offset, arrP, 0, arrP->Length); offset += arrP->Length; 
	Array::Copy(blob, offset, arrQ, 0, arrQ->Length); offset += arrQ->Length; 
	Array::Copy(blob, offset, arrG, 0, arrG->Length); offset += arrG->Length; 
	Array::Copy(blob, offset, arrY, 0, arrY->Length); offset += arrY->Length; 

	// раскодировать параметры
	Math::BigInteger^ P = Math::Convert::ToBigInteger(arrP, endian); 
	Math::BigInteger^ Q = Math::Convert::ToBigInteger(arrQ, endian); 
	Math::BigInteger^ G = Math::Convert::ToBigInteger(arrG, endian); 
	Math::BigInteger^ Y = Math::Convert::ToBigInteger(arrY, endian); 

	// закодировать параметры
	ASN1::IEncodable^ encodedParams = gcnew ASN1::ANSI::X942::DomainParameters(
		gcnew ASN1::Integer(P), gcnew ASN1::Integer(G), gcnew ASN1::Integer(Q), nullptr, nullptr
	); 
	// закодировать параметры алгоритма
	ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(gcnew ASN1::ObjectIdentifier(
            ASN1::ANSI::OID::x942_dh_public_key), encodedParams); 

	// закодировать значение ключа
	ASN1::BitString^ encodedKey = gcnew ASN1::BitString(ASN1::Integer(Y).Encoded); 

	// вернуть закодированный ключ и параметры
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
}

///////////////////////////////////////////////////////////////////////////
// Получить структуру для импорта параметров
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetParametersBlob(
	ANSI::X942::IParameters^ parameters, BCRYPT_DH_PARAMETER_HEADER* pBlob, DWORD cbBlob)
{$
	// закодировать параметры 
	array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters->P, Endian); 
    array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters->G, Endian);  

	// определить размер структуры параметров
	DWORD cb = sizeof(BCRYPT_DH_PARAMETER_HEADER) + 2 * arrP->Length; 

	// проверить достаточность буфера
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// обнулить выделенную память
	PBYTE pb = (PBYTE)pBlob + cb; memset(pBlob, 0, cb); 
	
	// указать сигнатуру параметров
	pBlob->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC; 

	// указать размеры параметров
	pBlob->cbLength = cb; pBlob->cbKeyLength = arrP->Length; 

	// скопировать параметры 
	Marshal::Copy(arrG, 0, IntPtr(pb - arrG->Length), arrG->Length); pb -= arrP->Length; 
	Marshal::Copy(arrP, 0, IntPtr(pb - arrP->Length), arrP->Length); pb -= arrP->Length;
	return cb; 
}

///////////////////////////////////////////////////////////////////////////
// Получить структуру для импорта открытого и личного ключа
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetKeyPairBlob(
	ANSI::X942::IPublicKey^ publicKey, ANSI::X942::IPrivateKey^ privateKey, 
	BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob)
{$
	// получить параметры ключа
	ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)privateKey->Parameters; 

	// закодировать компоненты ключа
	array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters->P, Endian); 

	// определить размер структуры импорта
	DWORD cb = sizeof(BCRYPT_DH_KEY_BLOB) + 4 * arrP->Length; 

	// проверить достаточность буфера
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// закодировать компоненты ключа
    array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters->G, Endian);  
	array<BYTE>^ arrY = Math::Convert::FromBigInteger(publicKey ->Y, Endian); 
    array<BYTE>^ arrX = Math::Convert::FromBigInteger(privateKey->X, Endian);  

	// указать сигнатуру структуры
	memset(pBlob, 0, cb); pBlob->dwMagic = BCRYPT_DH_PRIVATE_MAGIC; 
	
	// установить размер модуля в битах
	PBYTE pb = (PBYTE)pBlob + cb; pBlob->cbKey = arrP->Length; 

	// записать отдельные элементы
	Marshal::Copy(arrX, 0, IntPtr(pb - arrX->Length), arrX->Length); pb -= arrP->Length;  
	Marshal::Copy(arrY, 0, IntPtr(pb - arrY->Length), arrY->Length); pb -= arrP->Length;  
	Marshal::Copy(arrG, 0, IntPtr(pb - arrG->Length), arrG->Length); pb -= arrP->Length;  
	Marshal::Copy(arrP, 0, IntPtr(pb - arrP->Length), arrP->Length); pb -= arrP->Length;  
	return cb; 
}

///////////////////////////////////////////////////////////////////////////
// Получить структуру для импорта личного ключа
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetPrivateKeyBlob(
	ANSI::X942::IPrivateKey^ privateKey, BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob)
{$
	// проверить наличие буфера
	if (pBlob == nullptr) return GetKeyPairBlob(nullptr, privateKey, pBlob, cbBlob); 

	// получить параметры ключа
	ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)privateKey->Parameters; 

	// вычислить открытый ключ
	Math::BigInteger^ Y = parameters->G->ModPow(privateKey->X, parameters->P);

	// создать открытый ключ
	ANSI::X942::IPublicKey^ publicKey = gcnew ANSI::X942::PublicKey(
		privateKey->KeyFactory, parameters, Y
	); 
	// получить структуру для импорта личного ключа
	return GetKeyPairBlob(publicKey, privateKey, pBlob, cbBlob); 
}

///////////////////////////////////////////////////////////////////////////
// Получить структуру для импорта открытого ключа
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetPublicKeyBlob(
	ANSI::X942::IPublicKey^ publicKey, BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob)
{$
	// получить параметры ключа
	ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)publicKey->Parameters; 

	// закодировать компоненты личного ключа
	array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters->P, Endian); 
	array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters->G, Endian);  
	array<BYTE>^ arrY = Math::Convert::FromBigInteger(publicKey ->Y, Endian);  

	// определить размер структуры импорта
	DWORD cb = sizeof(BCRYPT_DH_KEY_BLOB) + 3 * arrP->Length; 

	// проверить достаточность буфера
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// указать сигнатуру структуры
	memset(pBlob, 0, cb); pBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC; 
	
	// установить размер модуля в битах
	PBYTE pb = (PBYTE)pBlob + cb; pBlob->cbKey = arrP->Length; 

	// записать отдельные элементы
	Marshal::Copy(arrY, 0, IntPtr(pb - arrY->Length), arrY->Length); pb -= arrP->Length;  
	Marshal::Copy(arrG, 0, IntPtr(pb - arrG->Length), arrG->Length); pb -= arrP->Length;  
	Marshal::Copy(arrP, 0, IntPtr(pb - arrP->Length), arrP->Length); pb -= arrP->Length;  
	return cb; 
}

