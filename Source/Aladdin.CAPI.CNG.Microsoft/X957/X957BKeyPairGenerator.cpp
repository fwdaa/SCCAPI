#include "..\stdafx.h"
#include "X957BKeyPairGenerator.h"
#include "X957Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957BKeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ 
Aladdin::CAPI::CNG::Microsoft::X957::BKeyPairGenerator::Generate(String^ keyOID)
{$
	// определить требуемый размер буфера
	DWORD cbParamBlob = Encoding::GetParametersBlob(parameters, 0, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ paramBlob = gcnew array<BYTE>(cbParamBlob); pin_ptr<BYTE> ptrParamBlob = &paramBlob[0]; 

	// выполнить преобразование типа
	BCRYPT_DSA_PARAMETER_HEADER* pParamBlob = (BCRYPT_DSA_PARAMETER_HEADER*)(PBYTE)ptrParamBlob; 

	// получить структуру для импорта параметров
	cbParamBlob = Encoding::GetParametersBlob(parameters, pParamBlob, cbParamBlob); 

	// сгенерировать пару ключей
	Using<CAPI::CNG::BKeyHandle^> hKeyPair(Handle->CreateKeyPair(pParamBlob->cbKeyLength * 8, 0));

	// установить параметры 
	hKeyPair.Get()->SetParam(BCRYPT_DSA_PARAMETERS, IntPtr(pParamBlob), cbParamBlob, 0); 

	// завершить создание пары ключей
	Handle->FinalizeKeyPair(hKeyPair.Get(), 0);

	// определить требуемый размер буфера
	DWORD cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_DSA_PRIVATE_BLOB, 0, IntPtr::Zero, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	BCRYPT_DSA_KEY_BLOB* pHeader = (BCRYPT_DSA_KEY_BLOB*)(PBYTE)ptrBlob; 

	// экспортировать личный ключ
	cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_DSA_PRIVATE_BLOB, 0, IntPtr(pHeader), cbBlob); 

	// выделить буферы требуемых размеров
	array<BYTE>^ arrY = gcnew array<BYTE>(pHeader->cbKey); 
	array<BYTE>^ arrX = gcnew array<BYTE>(20); 

	// определить смещение параметров
	DWORD offset = sizeof(BCRYPT_DSA_KEY_BLOB) + 2 * pHeader->cbKey; 
	
	// извлечь открытый и личный ключ
	Array::Copy(blob, offset, arrY,  0, arrY->Length); offset += arrY->Length; 
	Array::Copy(blob, offset, arrX,  0, arrX->Length); offset += arrX->Length; 

	// раскодировать открытый и личный ключ
	Math::BigInteger^ y = Math::Convert::ToBigInteger(arrY, Encoding::Endian); 
	Math::BigInteger^ x = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 

	// получить фабрику кодирования
	KeyFactory^ keyFactory = Factory->GetKeyFactory(keyOID); 

	// создать объект открытого ключа
	IPublicKey^ publicKey = gcnew ANSI::X957::PublicKey(keyFactory, parameters, y); 

	// создать объект личного ключа
	Using<IPrivateKey^> privateKey(gcnew ANSI::X957::PrivateKey(Factory, nullptr, keyOID, parameters, x)); 

    // вернуть созданную пару ключей
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr); 
}

