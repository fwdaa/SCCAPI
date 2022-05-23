#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAPKCS1NSignHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1NSignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� RSA
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PKCS1::NSignHash::Sign(
	SecurityObject^ scope, IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPrivateKey,  
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// ���������� ��� ��������� ����������� 
	BCRYPT_PKCS1_PADDING_INFO info  = { PrimitiveProvider::GetHashName(hashAlgorithm->Algorithm->Value) }; 

	// ��������� ���-��������
	return Sign(scope, hPrivateKey, IntPtr(&info), hash, BCRYPT_PAD_PKCS1);
}

