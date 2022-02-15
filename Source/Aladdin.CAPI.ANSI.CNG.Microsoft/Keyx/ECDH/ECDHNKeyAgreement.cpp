#include "..\..\stdafx.h"
#include "ECDHNKeyAgreement.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ECDHNKeyAgreement.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа
//////////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::ECDH::NKeyAgreement::DeriveKey(
	IParameters^ parameters, CAPI::CNG::NSecretHandle^ hSecret, array<BYTE>^ random, int keySize) 
{$
	// определить имя алгоритма хэширования
	pin_ptr<CONST WCHAR> szHash = PtrToStringChars(hashAlgorithm->Name); 

	// указать требуемый размер буфера
	DWORD cb = sizeof(NCryptBufferDesc) + sizeof(NCryptBuffer) * 2; std::vector<BYTE> vecParameters(cb); 

	// выделить буфер требуемого размера
	NCryptBufferDesc* pParameters = (NCryptBufferDesc*)&vecParameters[0]; 

	// указать версию параметров
	pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

	// перейти на отдельные параметры
	pParameters->pBuffers = (PNCryptBuffer)(pParameters + 1); 

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
