#include "..\..\stdafx.h"
#include "..\..\X942\X942Encoding.h"
#include "DHBKeyAgreement.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DHBKeyAgreement.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::DH::BKeyAgreement::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) 
{$
	// определить требуемый размер буфера
	DWORD cbBlob = X942::Encoding::GetPrivateKeyBlob((ANSI::X942::IPrivateKey^)privateKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DH_KEY_BLOB* pbBlob = (BCRYPT_DH_KEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = X942::Encoding::GetPrivateKeyBlob((ANSI::X942::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_DH_PRIVATE_BLOB, IntPtr(pbBlob), cbBlob, BCRYPT_NO_KEY_VALIDATION
	); 
}

Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::DH::BKeyAgreement::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey)
{$
	// определить требуемый размер буфера
	DWORD cbBlob = X942::Encoding::GetPublicKeyBlob((ANSI::X942::IPublicKey^)publicKey, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DH_KEY_BLOB* pbBlob = (BCRYPT_DH_KEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = X942::Encoding::GetPublicKeyBlob((ANSI::X942::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// импортировать открытый ключ
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_DH_PUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0
	); 
}

array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::DH::BKeyAgreement::DeriveKey(
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
	if (wrapOID != nullptr || (random != nullptr && random->Length > 0)) 
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
		array<BYTE>^ appendData = random; if (wrapOID != nullptr) 
		{
			// закодировать номер блока
			array<BYTE>^ counter = Math::Convert::FromInt32(i + 1, Endian);

			// закодировать данные для хэширования
			ASN1::ANSI::X942::KeySpecificInfo^ specificInfo = gcnew ASN1::ANSI::X942::KeySpecificInfo(
				gcnew ASN1::ObjectIdentifier(wrapOID), gcnew ASN1::OctetString(counter)
			);
			// закодировать случайные данные
			ASN1::OctetString^ partyAInfo = (random != nullptr) ? gcnew ASN1::OctetString(random) : nullptr; 

			// закодировать размер ключа шифрования ключа
			ASN1::OctetString^ suppPubInfo = gcnew ASN1::OctetString(
				Math::Convert::FromInt32(keySize * 8, Endian)
			); 
			// закодировать данные для хэширования
			ASN1::ANSI::X942::OtherInfo^ otherInfo = 
				gcnew ASN1::ANSI::X942::OtherInfo(specificInfo, partyAInfo, suppPubInfo); 

			// получить закодированное представление
			appendData = otherInfo->Encoded; 
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

