#include "..\..\stdafx.h"
#include "ECDHBKeyAgreement.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ECDHBKeyAgreement.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа
//////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::ECDH::BKeyAgreement::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey)
{$
	// определить требуемый размер буфера
	DWORD cbBlob = X962::Encoding::GetPrivateKeyBlob(algName, (ANSI::X962::IPrivateKey^)privateKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = X962::Encoding::GetPrivateKeyBlob(algName, (ANSI::X962::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_ECCPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, BCRYPT_NO_KEY_VALIDATION
	); 
}

Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::ECDH::BKeyAgreement::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey)
{$
	// определить требуемый размер буфера
	DWORD cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, BCRYPT_ECCPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0); 
}

array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::ECDH::BKeyAgreement::DeriveKey(
	IParameters^ parameters, CAPI::CNG::BSecretHandle^ hSecret, array<BYTE>^ random, int keySize) 
{$
	// определить имя алгоритма хэширования
	pin_ptr<CONST WCHAR> szHash = PtrToStringChars(hashAlgorithm->Name); 

	// указать требуемый размер буфера
	DWORD cb = sizeof(BCryptBufferDesc) + sizeof(BCryptBuffer) * 2; std::vector<BYTE> vecParameters(cb); 

	// выделить буфер требуемого размера
	BCryptBufferDesc* pParameters = (BCryptBufferDesc*)&vecParameters[0]; 

	// указать версию параметров
	pParameters->ulVersion = BCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

	// перейти на отдельные параметры
	pParameters->pBuffers = (PBCryptBuffer)(pParameters + 1); 

	// указать идентификатор параметра
	pParameters->pBuffers[0].BufferType = KDF_HASH_ALGORITHM; 

	// указать имя алгоритма хэширования
	pParameters->pBuffers[0].pvBuffer = (PWSTR)(PCWSTR)szHash; 

	// указать размер имени
	pParameters->pBuffers[0].cbBuffer = (hashAlgorithm->Name->Length + 1) * sizeof(WCHAR); 

	// при указании дополнительных данных
	if (wrapParameters != nullptr || (random != nullptr && random->Length > 0)) 
	{ 
		// указать идентификатор параметра
		pParameters->cBuffers = 2; pParameters->pBuffers[1].BufferType = KDF_SECRET_APPEND; 
	}
	// определить число блоков
	int blockSize = hashAlgorithm->HashSize; int blocks = (keySize + blockSize - 1) / blockSize; 

	// выделить память для ключей
	array<array<BYTE>^>^ keys = gcnew array<array<BYTE>^>(blocks); 

	// для каждого блока ключа шифрования ключа
	for (int i = 0; i < blocks; i++)
	{
		// указать дополняемые данные
		array<BYTE>^ appendData = random; if (wrapParameters != nullptr) 
		{
			// закодировать номер блока
			array<BYTE>^ counter = Math::Convert::FromInt32(i + 1, Endian);

            // закодировать случайные данные
            ASN1::OctetString^ entityUInfo = (random != nullptr) ? gcnew ASN1::OctetString(random) : nullptr; 

			// закодировать размер ключа шифрования ключа
			ASN1::OctetString^ suppPubInfo = gcnew ASN1::OctetString(
				Math::Convert::FromInt32(keySize * 8, Endian)
			); 
			// объединить закодированные данные
			ASN1::ANSI::X962::SharedInfo^ sharedInfo = gcnew ASN1::ANSI::X962::SharedInfo(
				wrapParameters, entityUInfo, nullptr, suppPubInfo, nullptr
			); 
			// объединить номер блока и закодированные данные
			appendData = Arrays::Concat(counter, sharedInfo->Encoded); 
		}
		// при отсутствии дополнительных данных
		if (appendData == nullptr || appendData->Length == 0)
		{
			// вычислить часть ключа
			keys[i] = hSecret->DeriveKey(BCRYPT_KDF_HASH, blockSize, IntPtr(pParameters), 0); 
		}
		else {
			// определить адрес буфера
			pin_ptr<BYTE> ptrEncoded = &appendData[0]; 

			// указать значение параметра
			pParameters->pBuffers[1].pvBuffer = ptrEncoded; 

			// указать размер параметра
			pParameters->pBuffers[1].cbBuffer = appendData->Length; 
		
			// вычислить часть ключа
			keys[i] = hSecret->DeriveKey(BCRYPT_KDF_HASH, blockSize, IntPtr(pParameters), 0); 
		}
		// проверить размер ключа
		if (keys[i]->Length != blockSize) throw gcnew InvalidOperationException(); 
	}
	// объединить части ключа
	return Arrays::CopyOf(Arrays::Concat(keys), keySize); 
}

