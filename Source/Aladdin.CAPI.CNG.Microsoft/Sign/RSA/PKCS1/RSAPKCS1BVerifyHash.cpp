#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "..\..\..\RSA\RSAEncoding.h"
#include "RSAPKCS1BVerifyHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1BVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� RSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PKCS1::BVerifyHash::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) 
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = Microsoft::RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = Microsoft::RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// ������������� �������� ����
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_RSAPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0
	); 
}

void Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PKCS1::BVerifyHash::Verify(
	IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// ���������� ��� ��������� ����������� 
	BCRYPT_PKCS1_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashAlgorithm->Algorithm->Value) }; 

	// ��������� ������� ���-��������
	hPublicKey->VerifySignature(IntPtr(&info), hash, signature, BCRYPT_PAD_PKCS1);   
}

