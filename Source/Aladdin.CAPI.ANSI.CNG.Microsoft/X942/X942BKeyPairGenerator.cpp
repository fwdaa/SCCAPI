#include "..\stdafx.h"
#include "X942BKeyPairGenerator.h"
#include "X942Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942BKeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X942::BKeyPairGenerator::Generate(String^ keyOID)
{$
	// определить требуемый размер буфера
	DWORD cbParamBlob = Encoding::GetParametersBlob(parameters, 0, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ paramBlob = gcnew array<BYTE>(cbParamBlob); pin_ptr<BYTE> ptrParamBlob = &paramBlob[0]; 

	// выполнить преобразование типа
	BCRYPT_DH_PARAMETER_HEADER* pParamBlob = (BCRYPT_DH_PARAMETER_HEADER*)(PBYTE)ptrParamBlob; 

	// получить структуру для импорта параметров
	cbParamBlob = Encoding::GetParametersBlob(parameters, pParamBlob, cbParamBlob); 

	// сгенерировать пару ключей
	Using<CAPI::CNG::BKeyHandle^> hKeyPair(Handle->CreateKeyPair(pParamBlob->cbKeyLength * 8, 0));

	// установить параметры 
	hKeyPair.Get()->SetParam(BCRYPT_DH_PARAMETERS, IntPtr(pParamBlob), cbParamBlob, 0); 

	// завершить создание пары ключей
	Handle->FinalizeKeyPair(hKeyPair.Get(), 0);

	// определить требуемый размер буфера
	DWORD cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_DH_PRIVATE_BLOB, 0, IntPtr::Zero, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	BCRYPT_DH_KEY_BLOB* pHeader = (BCRYPT_DH_KEY_BLOB*)(PBYTE)ptrBlob; 

	// экспортировать личный ключ
	cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_DH_PRIVATE_BLOB, 0, IntPtr(pHeader), cbBlob); 

	// выделить буферы требуемых размеров
	array<BYTE>^ arrY = gcnew array<BYTE>(pHeader->cbKey); 
	array<BYTE>^ arrX = gcnew array<BYTE>(pHeader->cbKey); 

	// указать начальную позицию для считывания
	DWORD offset = sizeof(BCRYPT_DH_KEY_BLOB) + 2 * pHeader->cbKey; 
	
	// извлечь открытый и личный ключ
	Array::Copy(blob, offset, arrY,  0, pHeader->cbKey); offset += pHeader->cbKey; 
	Array::Copy(blob, offset, arrX,  0, pHeader->cbKey); offset += pHeader->cbKey; 

	// раскодировать открытый и личный ключ
	Math::BigInteger^ y = Math::Convert::ToBigInteger(arrY, Encoding::Endian); 
	Math::BigInteger^ x = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 

	// получить фабрику кодирования
	KeyFactory^ keyFactory = Factory->GetKeyFactory(keyOID); 

	// создать объект открытого ключа
	IPublicKey^ publicKey = gcnew ANSI::X942::PublicKey (keyFactory, parameters, y); 

	// создать объект личного ключа
	Using<IPrivateKey^> privateKey(gcnew ANSI::X942::PrivateKey(Factory, nullptr, keyOID, parameters, x)); 

    // вернуть созданную пару ключей
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr);  
}

