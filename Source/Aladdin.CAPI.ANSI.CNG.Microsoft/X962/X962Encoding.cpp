#include "..\stdafx.h"
#include "X962Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X962Encoding.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Определить имя алгоритма
///////////////////////////////////////////////////////////////////////////
String^ Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetKeyName(
	ANSI::X962::IParameters^ parameters, DWORD keyType)
{$
	// проверить тип параметров
	if (dynamic_cast<INamedParameters^>(parameters) == nullptr) throw gcnew NotSupportedException(); 

	// извлечь идентификатор параметров
	String^ paramOID = ((INamedParameters^)parameters)->Oid; 

	if (paramOID == ASN1::ANSI::OID::x962_curves_prime256v1)
	{
		// указать имя алгоритма
		return (keyType == AT_SIGNATURE) ? BCRYPT_ECDSA_P256_ALGORITHM : BCRYPT_ECDH_P256_ALGORITHM; 
	}
	else if (paramOID == ASN1::ANSI::OID::certicom_curves_secp384r1)
	{
		// указать имя алгоритма
		return (keyType == AT_SIGNATURE) ? BCRYPT_ECDSA_P384_ALGORITHM : BCRYPT_ECDH_P384_ALGORITHM; 
	}
	else if (paramOID == ASN1::ANSI::OID::certicom_curves_secp521r1)
	{
		// указать имя алгоритма
		return (keyType == AT_SIGNATURE) ? BCRYPT_ECDSA_P521_ALGORITHM : BCRYPT_ECDH_P521_ALGORITHM; 
	}
	// при ошибке выбросить исключение
	else throw gcnew NotSupportedException(); 
}

///////////////////////////////////////////////////////////////////////////
// Преобразовать формат открытого ключа
///////////////////////////////////////////////////////////////////////////
Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetPublicKeyInfo(
	CAPI::CNG::NKeyHandle^ hPublicKey)
{$
	// определить требуемый размер буфера
	DWORD cbBlob = hPublicKey->Export(nullptr, BCRYPT_ECCPUBLIC_BLOB, 0, IntPtr::Zero, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 
	
	// выполнить преобразование типа
	BCRYPT_ECCKEY_BLOB* pBlob = (BCRYPT_ECCKEY_BLOB*)(PBYTE)ptrBlob; 

	// экспортировать открытый ключ
	cbBlob = hPublicKey->Export(nullptr, BCRYPT_ECCPUBLIC_BLOB, 0, IntPtr(pBlob), cbBlob); 

	// в зависимости от типа ключа
	String^ paramOID = nullptr; switch (pBlob->dwMagic)
	{
	// указать идентификатор параметров
	case BCRYPT_ECDSA_PUBLIC_P256_MAGIC: paramOID = ASN1::ANSI::OID::x962_curves_prime256v1;    break; 
	case BCRYPT_ECDH_PUBLIC_P256_MAGIC : paramOID = ASN1::ANSI::OID::x962_curves_prime256v1;    break; 
	case BCRYPT_ECDSA_PUBLIC_P384_MAGIC: paramOID = ASN1::ANSI::OID::certicom_curves_secp384r1; break; 
	case BCRYPT_ECDH_PUBLIC_P384_MAGIC : paramOID = ASN1::ANSI::OID::certicom_curves_secp384r1; break; 
	case BCRYPT_ECDSA_PUBLIC_P521_MAGIC: paramOID = ASN1::ANSI::OID::certicom_curves_secp521r1; break; 
	case BCRYPT_ECDH_PUBLIC_P521_MAGIC : paramOID = ASN1::ANSI::OID::certicom_curves_secp521r1; break; 

	// при ошибке выбросить исключение
	default: throw gcnew NotSupportedException(); 
	}
	// выделить память для параметров
	array<BYTE>^ arrX = gcnew array<BYTE>(pBlob->cbKey); 
	array<BYTE>^ arrY = gcnew array<BYTE>(pBlob->cbKey); 

	// определить смещение параметров
	DWORD offset = sizeof(BCRYPT_ECCKEY_BLOB); 

	// прочитать параметры
	Array::Copy(blob, offset, arrX, 0, arrX->Length); offset += arrX->Length; 
	Array::Copy(blob, offset, arrY, 0, arrY->Length); offset += arrY->Length; 

	// раскодировать параметры
	Math::BigInteger^ X = Math::Convert::ToBigInteger(arrX, Endian); 
	Math::BigInteger^ Y = Math::Convert::ToBigInteger(arrY, Endian); 

	// указать фабрику кодирования ключей
	ANSI::X962::KeyFactory^ keyFactory = gcnew ANSI::X962::KeyFactory(
		ASN1::ANSI::OID::x962_ec_public_key
	); 
	// раскодировать параметры алгоритма
	ANSI::X962::IParameters^ ecParameters = (ANSI::X962::IParameters^)
		keyFactory->DecodeParameters(gcnew ASN1::ObjectIdentifier(paramOID)); 

	// создать открытый ключ
	IPublicKey^ publicKey = gcnew ANSI::X962::PublicKey(
		keyFactory, ecParameters, gcnew EC::Point(X, Y)
	); 
	// закодировать открытый ключ
	return keyFactory->EncodePublicKey(publicKey); 
}

///////////////////////////////////////////////////////////////////////////
// Получить структуру для импорта открытого и личного ключа
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetKeyPairBlob(String^ algName, 
	ANSI::X962::IPublicKey^ publicKey, ANSI::X962::IPrivateKey^ privateKey, 
	BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob)
{$
	// получить параметры ключа
	ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)privateKey->Parameters; 

	// указать используемое поле
	EC::FieldFp^ field = (EC::FieldFp^)parameters->Curve->Field; 

	// определить размер координат 
	DWORD cbKey = (field->P->BitLength + 7) / 8; 

	// определить размер структуры импорта
	DWORD cb = sizeof(BCRYPT_ECCKEY_BLOB) + 3 * cbKey; 

	// проверить достаточность буфера
	if (pBlob == nullptr) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// указать сигнатуру структуры
	memset(pBlob, 0, cb); pBlob->cbKey = cbKey; 

	// указать тип ключа
	     if (algName == BCRYPT_ECDSA_P256_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC; 
	else if (algName == BCRYPT_ECDH_P256_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC; 
	else if (algName == BCRYPT_ECDSA_P384_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC; 
	else if (algName == BCRYPT_ECDH_P384_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PRIVATE_P384_MAGIC; 
	else if (algName == BCRYPT_ECDSA_P521_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC; 
	else if (algName == BCRYPT_ECDH_P521_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PRIVATE_P521_MAGIC; 

	// при ошибке выбросить исключение
	else throw gcnew NotSupportedException(); 
	
	// извлечь координаты точки
	Math::BigInteger^ X = (Math::BigInteger^)publicKey->Q->X; 
	Math::BigInteger^ Y = (Math::BigInteger^)publicKey->Q->Y; 

	// закодировать компоненты личного ключа
	array<BYTE>^ arrX = Math::Convert::FromBigInteger(X,             Endian, cbKey); 
	array<BYTE>^ arrY = Math::Convert::FromBigInteger(Y,             Endian, cbKey); 
    array<BYTE>^ arrD = Math::Convert::FromBigInteger(privateKey->D, Endian, cbKey);  

	// перейти на описание параметров
	PBYTE pbParams = (PBYTE)(pBlob + 1); DWORD offset = 0; 

	// записать отдельные элементы
	Marshal::Copy(arrX, 0, IntPtr(pbParams + offset), arrX->Length); offset += arrX->Length;  
	Marshal::Copy(arrY, 0, IntPtr(pbParams + offset), arrY->Length); offset += arrY->Length;  
	Marshal::Copy(arrD, 0, IntPtr(pbParams + offset), arrD->Length); offset += arrD->Length;  

	return cb; 
}

///////////////////////////////////////////////////////////////////////////
// Получить структуру для импорта личного ключа
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetPrivateKeyBlob(String^ algName, 
	ANSI::X962::IPrivateKey^ privateKey, BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob)
{$
	// проверить наличие буфера
	if (pBlob == nullptr) return GetKeyPairBlob(algName, nullptr, privateKey, pBlob, cbBlob); 

	// получить параметры ключа
	ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)privateKey->Parameters; 

    // умножить базовую точку на число
    EC::Point^ Q = parameters->Curve->Multiply(parameters->Generator, privateKey->D); 

	// создать открытый ключ
	ANSI::X962::IPublicKey^ publicKey = gcnew ANSI::X962::PublicKey(
		privateKey->KeyFactory, parameters, Q
	); 
	// получить структуру для импорта личного ключа
	return GetKeyPairBlob(algName, publicKey, privateKey, pBlob, cbBlob); 
}

///////////////////////////////////////////////////////////////////////////
// Получить структуру для импорта открытого ключа
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetPublicKeyBlob(String^ algName, 
	ANSI::X962::IPublicKey^ publicKey, BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob)
{$
	// получить параметры ключа
	ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)publicKey->Parameters; 

	// указать используемое поле
	EC::FieldFp^ field = (EC::FieldFp^)parameters->Curve->Field; 

	// определить размер координат 
	DWORD cbKey = (field->P->BitLength + 7) / 8; 

	// определить размер структуры импорта
	DWORD cb = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cbKey; 

	// проверить достаточность буфера
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// указать сигнатуру структуры
	memset(pBlob, 0, cb); pBlob->cbKey = cbKey; 

	// указать тип ключа
	     if (algName == BCRYPT_ECDSA_P256_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC; 
	else if (algName == BCRYPT_ECDH_P256_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC; 
	else if (algName == BCRYPT_ECDSA_P384_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC; 
	else if (algName == BCRYPT_ECDH_P384_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC; 
	else if (algName == BCRYPT_ECDSA_P521_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC; 
	else if (algName == BCRYPT_ECDH_P521_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PUBLIC_P521_MAGIC; 

	// при ошибке выбросить исключение
	else throw gcnew NotSupportedException(); 
	
	// извлечь координаты точки
	Math::BigInteger^ X = (Math::BigInteger^)publicKey->Q->X; 
	Math::BigInteger^ Y = (Math::BigInteger^)publicKey->Q->Y; 

	// закодировать компоненты личного ключа
	array<BYTE>^ arrX = Math::Convert::FromBigInteger(X, Endian, cbKey); 
	array<BYTE>^ arrY = Math::Convert::FromBigInteger(Y, Endian, cbKey); 

	// перейти на описание параметров
	PBYTE pbParams = (PBYTE)(pBlob + 1); DWORD offset = 0; 

	// записать отдельные элементы
	Marshal::Copy(arrX, 0, IntPtr(pbParams + offset), arrX->Length); offset += arrX->Length;  
	Marshal::Copy(arrY, 0, IntPtr(pbParams + offset), arrY->Length); offset += arrY->Length;  

	return cb; 
}

///////////////////////////////////////////////////////////////////////
// Кодирование подписи ECDSA
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::EncodeSignature(
	ANSI::X962::IParameters^ parameters, ASN1::ANSI::X962::ECDSASigValue^ signature)
{$
    // определить параметр алгоритма
    int bytesR = (parameters->Order->BitLength + 7) / 8; 

	// закодировать параметры R и S
	array<BYTE>^ R = Math::Convert::FromBigInteger(signature->R->Value, Endian, bytesR); 
	array<BYTE>^ S = Math::Convert::FromBigInteger(signature->S->Value, Endian, bytesR); 

	// объединить параметры R и S
	return Arrays::Concat(R, S); 
}

Aladdin::ASN1::ANSI::X962::ECDSASigValue^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::DecodeSignature(
	ANSI::X962::IParameters^ parameters, array<BYTE>^ encoded)
{$
    // определить параметр алгоритма
    int bytesR = (parameters->Order->BitLength + 7) / 8; int bytesS = encoded->Length - bytesR; 

	// проверить размер подписи
	if (bytesS <= 0) throw gcnew InvalidDataException(); 

	// раскодировать параметры R и S
	Math::BigInteger^ R = Math::Convert::ToBigInteger(encoded,      0, bytesR, Endian); 
	Math::BigInteger^ S = Math::Convert::ToBigInteger(encoded, bytesR, bytesS, Endian); 

	// закодировать подпись
	return gcnew ASN1::ANSI::X962::ECDSASigValue(
		gcnew ASN1::Integer(R), gcnew ASN1::Integer(S), nullptr, nullptr
	); 
}


