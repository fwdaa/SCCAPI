#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "..\..\..\RSA\RSAEncoding.h"
#include "RSAPKCS1BSignHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1BSignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� RSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PKCS1::BSignHash::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) 
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = Microsoft::RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = Microsoft::RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// ������������� �������� ����
	return hProvider->ImportKeyPair(nullptr, 
		BCRYPT_RSAFULLPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, 0
	); 
}

array<BYTE>^ Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PKCS1::BSignHash::Sign(
	IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// ���������� ��� ��������� ����������� 
	BCRYPT_PKCS1_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashAlgorithm->Algorithm->Value) }; 

	// ��������� ���-��������
	return hPrivateKey->SignHash(IntPtr(&info), hash, BCRYPT_PAD_PKCS1);
}
