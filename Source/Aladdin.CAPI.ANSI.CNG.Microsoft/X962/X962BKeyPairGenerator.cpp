#include "..\stdafx.h"
#include "X962BKeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X962BKeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X962::BKeyPairGenerator::Generate(String^ keyOID)
{$
	// сгенерировать пару ключей
	Using<CAPI::CNG::BKeyHandle^> hKeyPair(Handle->CreateKeyPair(0, 0));

	// завершить создание пары ключей
	Handle->FinalizeKeyPair(hKeyPair.Get(), 0);

	// определить требуемый размер буфера
	DWORD cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_ECCPRIVATE_BLOB, 0, IntPtr::Zero, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	BCRYPT_ECCKEY_BLOB* pHeader = (BCRYPT_ECCKEY_BLOB*)(PBYTE)ptrBlob; 

	// экспортировать личный ключ
	cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_ECCPRIVATE_BLOB, 0, IntPtr(pHeader), cbBlob); 

	// в зависимости от типа ключа
	String^ paramOID = nullptr; switch (pHeader->dwMagic)
	{
	// указать идентификатор параметров
	case BCRYPT_ECDSA_PRIVATE_P256_MAGIC: paramOID = ASN1::ANSI::OID::x962_curves_prime256v1;    break; 
	case BCRYPT_ECDH_PRIVATE_P256_MAGIC : paramOID = ASN1::ANSI::OID::x962_curves_prime256v1;    break; 
	case BCRYPT_ECDSA_PRIVATE_P384_MAGIC: paramOID = ASN1::ANSI::OID::certicom_curves_secp384r1; break; 
	case BCRYPT_ECDH_PRIVATE_P384_MAGIC : paramOID = ASN1::ANSI::OID::certicom_curves_secp384r1; break; 
	case BCRYPT_ECDSA_PRIVATE_P521_MAGIC: paramOID = ASN1::ANSI::OID::certicom_curves_secp521r1; break; 
	case BCRYPT_ECDH_PRIVATE_P521_MAGIC : paramOID = ASN1::ANSI::OID::certicom_curves_secp521r1; break; 

	// при ошибке выбросить исключение
	default: throw gcnew NotSupportedException(); 
	}
	// выделить буферы требуемых размеров
	array<BYTE>^ arrX = gcnew array<BYTE>(pHeader->cbKey); 
	array<BYTE>^ arrY = gcnew array<BYTE>(pHeader->cbKey); 
	array<BYTE>^ arrD = gcnew array<BYTE>(pHeader->cbKey); 

	// указать начальную позицию для считывания
	DWORD offset = sizeof(BCRYPT_ECCKEY_BLOB); 
	
	// извлечь открытый и личный ключ
	Array::Copy(blob, offset, arrX,  0, pHeader->cbKey); offset += pHeader->cbKey; 
	Array::Copy(blob, offset, arrY,  0, pHeader->cbKey); offset += pHeader->cbKey; 
	Array::Copy(blob, offset, arrD,  0, pHeader->cbKey); offset += pHeader->cbKey; 

	// раскодировать открытый и личный ключ
	Math::BigInteger^ X = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 
	Math::BigInteger^ Y = Math::Convert::ToBigInteger(arrY, Encoding::Endian); 
	Math::BigInteger^ D = Math::Convert::ToBigInteger(arrD, Encoding::Endian); 

	// указать фабрику кодирования ключей
	ANSI::X962::KeyFactory^ keyFactory = (ANSI::X962::KeyFactory^)Factory->GetKeyFactory(keyOID); 

	// раскодировать параметры алгоритма
	ANSI::X962::IParameters^ ecParameters = (ANSI::X962::IParameters^)
	    keyFactory->DecodeParameters(gcnew ASN1::ObjectIdentifier(paramOID)); 

	// создать объект открытого ключа
	IPublicKey^ publicKey = gcnew ANSI::X962::PublicKey(
		keyFactory, ecParameters, gcnew EC::Point(X, Y)
	); 
	// создать объект личного ключа
	Using<IPrivateKey^> privateKey(gcnew ANSI::X962::PrivateKey(
	    Factory, nullptr, keyFactory->KeyOID, ecParameters, D
	)); 
    // вернуть созданную пару ключей
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr);  
}

