#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAPSSBSignHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPSSBSignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� RSA PSS
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Microsoft::Sign::RSA::PSS::BSignHash::Sign(
	IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// ���������� ��� ��������� ����������� 
	BCRYPT_PSS_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashOID), (UINT)saltLength }; 

	// ��������� ���-��������
	return hPrivateKey->SignHash(IntPtr(&info), hash, BCRYPT_PAD_PSS);
}

