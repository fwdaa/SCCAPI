#include "..\stdafx.h"
#include "GOST34310KeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310KeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::Tumar::GOST34310::KeyPairGenerator::Generate(
	CAPI::CSP::Container^ container, String^ keyOID, DWORD keyType, DWORD keyFlags) 
{$
	// � ����������� �� ���� �����
	ALG_ID algID = 0; if (keyType == AT_KEYEXCHANGE)
	{
		// ������� ������������� �����
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a_xch) algID = CALG_EC256_512G_A_Xch; else
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b_xch) algID = CALG_EC256_512G_B_Xch; else

		// ��� ������ ��������� ����������
		throw gcnew NotSupportedException(); 
	}
	else {
		// ������� ������������� �����
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a) algID = CALG_EC256_512G_A; else
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b) algID = CALG_EC256_512G_B; else
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_c) algID = CALG_EC256_512G_C; else

		// ��� ������ ��������� ����������
		throw gcnew NotSupportedException(); 
	}
	// ������� ���� ������
	return Generate(container, algID, keyFlags);
}

