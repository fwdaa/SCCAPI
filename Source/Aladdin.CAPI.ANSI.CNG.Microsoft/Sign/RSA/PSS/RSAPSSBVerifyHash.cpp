#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAPSSBVerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPSSBVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� RSA PSS
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::ANSI::CNG::Microsoft::Sign::RSA::PSS::BVerifyHash::Verify(
	IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// ���������� ��� ��������� ����������� 
	BCRYPT_PSS_PADDING_INFO info = { PrimitiveProvider::GetHashName(hashOID), (UINT)saltLength }; 

	// ��������� ������� ���-��������
	hPublicKey->VerifySignature(IntPtr(&info), hash, signature, BCRYPT_PAD_PSS);   
}

