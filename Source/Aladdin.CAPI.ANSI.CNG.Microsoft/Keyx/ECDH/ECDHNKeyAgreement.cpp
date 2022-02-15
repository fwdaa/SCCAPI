#include "..\..\stdafx.h"
#include "ECDHNKeyAgreement.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ECDHNKeyAgreement.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// �������� ������������ ������ �����
//////////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::ECDH::NKeyAgreement::DeriveKey(
	IParameters^ parameters, CAPI::CNG::NSecretHandle^ hSecret, array<BYTE>^ random, int keySize) 
{$
	// ���������� ��� ��������� �����������
	pin_ptr<CONST WCHAR> szHash = PtrToStringChars(hashAlgorithm->Name); 

	// ������� ��������� ������ ������
	DWORD cb = sizeof(NCryptBufferDesc) + sizeof(NCryptBuffer) * 2; std::vector<BYTE> vecParameters(cb); 

	// �������� ����� ���������� �������
	NCryptBufferDesc* pParameters = (NCryptBufferDesc*)&vecParameters[0]; 

	// ������� ������ ����������
	pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

	// ������� �� ��������� ���������
	pParameters->pBuffers = (PNCryptBuffer)(pParameters + 1); 

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
