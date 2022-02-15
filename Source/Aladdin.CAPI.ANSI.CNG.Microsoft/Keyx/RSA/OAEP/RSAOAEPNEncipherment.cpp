#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAOAEPNEncipherment.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAOAEPNEncipherment.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������������� ���������� ������ RSA OAEP
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::RSA::OAEP::NEncipherment::NEncipherment(
	CAPI::CNG::NProvider^ provider, String^ hashOID, array<BYTE>^ label) 
			
	// ��������� ���������� ���������
	: RSA::PKCS1::NEncipherment(provider) 
{
	// ������� ��������� ��������� �����������
	ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
			gcnew ASN1::ObjectIdentifier(hashOID), ASN1::Null::Instance
	); 
	// ������� ������� ����������
	Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

	// ������� �������� �����������
	Using<CAPI::Hash^> hashAlgorithm(
		factory.Get()->CreateAlgorithm<CAPI::Hash^>(nullptr, hashParameters)
	); 
	// ���������� ������ ���-��������
	this->hashSize = hashAlgorithm.Get()->HashSize; 

	// ��������� ���������� ���������
	this->hashOID = hashOID; this->label = label;
}

array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::RSA::OAEP::NEncipherment::Encrypt(
	CAPI::CNG::NKeyHandle^ hPublicKey, array<BYTE>^ data)
{$
	// ���������� ��������� ������ ������
	DWORD cbInfo = sizeof(BCRYPT_OAEP_PADDING_INFO) + label->Length; std::vector<BYTE> vecInfo(cbInfo); 

	// �������� ����� ���������� �������
	BCRYPT_OAEP_PADDING_INFO* pInfo = (BCRYPT_OAEP_PADDING_INFO*)&vecInfo[0]; 

	// ���������� ��� ��������� ����������� 
	pInfo->pszAlgId = PrimitiveProvider::GetHashName(hashOID); 

	// ���������� ��������� �� �����
	pInfo->pbLabel = (PBYTE)(pInfo + 1); pInfo->cbLabel = label->Length; 

	// ����������� �����
	Marshal::Copy(label, 0, IntPtr(pInfo->pbLabel), pInfo->cbLabel); 

	// ����������� ������
	return hPublicKey->Encrypt(IntPtr(pInfo), data, BCRYPT_PAD_OAEP); 
}

