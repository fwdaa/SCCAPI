#include "..\..\stdafx.h"
#include "ECDHBKeyAgreement.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ECDHBKeyAgreement.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// �������� ������������ ������ �����
//////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::ECDH::BKeyAgreement::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey)
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = X962::Encoding::GetPrivateKeyBlob(algName, (ANSI::X962::IPrivateKey^)privateKey, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = X962::Encoding::GetPrivateKeyBlob(algName, (ANSI::X962::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// ������������� �������� ����
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_ECCPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, BCRYPT_NO_KEY_VALIDATION
	); 
}

Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::ECDH::BKeyAgreement::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey)
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// ������������� �������� ����
	return hProvider->ImportKeyPair(nullptr, BCRYPT_ECCPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0); 
}

array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::ECDH::BKeyAgreement::DeriveKey(
	IParameters^ parameters, CAPI::CNG::BSecretHandle^ hSecret, array<BYTE>^ random, int keySize) 
{$
	// ���������� ��� ��������� �����������
	pin_ptr<CONST WCHAR> szHash = PtrToStringChars(hashAlgorithm->Name); 

	// ������� ��������� ������ ������
	DWORD cb = sizeof(BCryptBufferDesc) + sizeof(BCryptBuffer) * 2; std::vector<BYTE> vecParameters(cb); 

	// �������� ����� ���������� �������
	BCryptBufferDesc* pParameters = (BCryptBufferDesc*)&vecParameters[0]; 

	// ������� ������ ����������
	pParameters->ulVersion = BCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

	// ������� �� ��������� ���������
	pParameters->pBuffers = (PBCryptBuffer)(pParameters + 1); 

	// ������� ������������� ���������
	pParameters->pBuffers[0].BufferType = KDF_HASH_ALGORITHM; 

	// ������� ��� ��������� �����������
	pParameters->pBuffers[0].pvBuffer = (PWSTR)(PCWSTR)szHash; 

	// ������� ������ �����
	pParameters->pBuffers[0].cbBuffer = (hashAlgorithm->Name->Length + 1) * sizeof(WCHAR); 

	// ��� �������� �������������� ������
	if (wrapParameters != nullptr || (random != nullptr && random->Length > 0)) 
	{ 
		// ������� ������������� ���������
		pParameters->cBuffers = 2; pParameters->pBuffers[1].BufferType = KDF_SECRET_APPEND; 
	}
	// ���������� ����� ������
	int blockSize = hashAlgorithm->HashSize; int blocks = (keySize + blockSize - 1) / blockSize; 

	// �������� ������ ��� ������
	array<array<BYTE>^>^ keys = gcnew array<array<BYTE>^>(blocks); 

	// ��� ������� ����� ����� ���������� �����
	for (int i = 0; i < blocks; i++)
	{
		// ������� ����������� ������
		array<BYTE>^ appendData = random; if (wrapParameters != nullptr) 
		{
			// ������������ ����� �����
			array<BYTE>^ counter = Math::Convert::FromInt32(i + 1, Endian);

            // ������������ ��������� ������
            ASN1::OctetString^ entityUInfo = (random != nullptr) ? gcnew ASN1::OctetString(random) : nullptr; 

			// ������������ ������ ����� ���������� �����
			ASN1::OctetString^ suppPubInfo = gcnew ASN1::OctetString(
				Math::Convert::FromInt32(keySize * 8, Endian)
			); 
			// ���������� �������������� ������
			ASN1::ANSI::X962::SharedInfo^ sharedInfo = gcnew ASN1::ANSI::X962::SharedInfo(
				wrapParameters, entityUInfo, nullptr, suppPubInfo, nullptr
			); 
			// ���������� ����� ����� � �������������� ������
			appendData = Arrays::Concat(counter, sharedInfo->Encoded); 
		}
		// ��� ���������� �������������� ������
		if (appendData == nullptr || appendData->Length == 0)
		{
			// ��������� ����� �����
			keys[i] = hSecret->DeriveKey(BCRYPT_KDF_HASH, blockSize, IntPtr(pParameters), 0); 
		}
		else {
			// ���������� ����� ������
			pin_ptr<BYTE> ptrEncoded = &appendData[0]; 

			// ������� �������� ���������
			pParameters->pBuffers[1].pvBuffer = ptrEncoded; 

			// ������� ������ ���������
			pParameters->pBuffers[1].cbBuffer = appendData->Length; 
		
			// ��������� ����� �����
			keys[i] = hSecret->DeriveKey(BCRYPT_KDF_HASH, blockSize, IntPtr(pParameters), 0); 
		}
		// ��������� ������ �����
		if (keys[i]->Length != blockSize) throw gcnew InvalidOperationException(); 
	}
	// ���������� ����� �����
	return Arrays::CopyOf(Arrays::Concat(keys), keySize); 
}

