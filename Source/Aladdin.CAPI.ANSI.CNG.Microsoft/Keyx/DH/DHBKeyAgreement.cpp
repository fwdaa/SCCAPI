#include "..\..\stdafx.h"
#include "..\..\X942\X942Encoding.h"
#include "DHBKeyAgreement.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DHBKeyAgreement.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::DH::BKeyAgreement::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) 
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = X942::Encoding::GetPrivateKeyBlob((ANSI::X942::IPrivateKey^)privateKey, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DH_KEY_BLOB* pbBlob = (BCRYPT_DH_KEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = X942::Encoding::GetPrivateKeyBlob((ANSI::X942::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// ������������� �������� ����
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_DH_PRIVATE_BLOB, IntPtr(pbBlob), cbBlob, BCRYPT_NO_KEY_VALIDATION
	); 
}

Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::DH::BKeyAgreement::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey)
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = X942::Encoding::GetPublicKeyBlob((ANSI::X942::IPublicKey^)publicKey, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DH_KEY_BLOB* pbBlob = (BCRYPT_DH_KEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = X942::Encoding::GetPublicKeyBlob((ANSI::X942::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// ������������� �������� ����
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_DH_PUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0
	); 
}

array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::DH::BKeyAgreement::DeriveKey(
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
	if (wrapOID != nullptr || (random != nullptr && random->Length > 0)) 
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
		array<BYTE>^ appendData = random; if (wrapOID != nullptr) 
		{
			// ������������ ����� �����
			array<BYTE>^ counter = Math::Convert::FromInt32(i + 1, Endian);

			// ������������ ������ ��� �����������
			ASN1::ANSI::X942::KeySpecificInfo^ specificInfo = gcnew ASN1::ANSI::X942::KeySpecificInfo(
				gcnew ASN1::ObjectIdentifier(wrapOID), gcnew ASN1::OctetString(counter)
			);
			// ������������ ��������� ������
			ASN1::OctetString^ partyAInfo = (random != nullptr) ? gcnew ASN1::OctetString(random) : nullptr; 

			// ������������ ������ ����� ���������� �����
			ASN1::OctetString^ suppPubInfo = gcnew ASN1::OctetString(
				Math::Convert::FromInt32(keySize * 8, Endian)
			); 
			// ������������ ������ ��� �����������
			ASN1::ANSI::X942::OtherInfo^ otherInfo = 
				gcnew ASN1::ANSI::X942::OtherInfo(specificInfo, partyAInfo, suppPubInfo); 

			// �������� �������������� �������������
			appendData = otherInfo->Encoded; 
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

