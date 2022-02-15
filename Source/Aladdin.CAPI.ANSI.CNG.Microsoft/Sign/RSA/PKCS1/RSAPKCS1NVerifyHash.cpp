#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAPKCS1NVerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1NVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� RSA
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::ANSI::CNG::Microsoft::Sign::RSA::PKCS1::NVerifyHash::Verify(
	IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPublicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// ���������� ��� ��������� ����������� 
	BCRYPT_PKCS1_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashAlgorithm->Algorithm->Value) };  

	// ��������� ������� ���-��������
	hPublicKey->VerifySignature(IntPtr(&info), hash, signature, BCRYPT_PAD_PKCS1);   
}

