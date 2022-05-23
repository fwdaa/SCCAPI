#include "..\stdafx.h"
#include "HMAC_GOSTR3411_1994.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "HMAC_GOSTR3411_1994.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� HMAC ���� � 34.11-1994
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::MAC::HMAC_GOSTR3411_1994::Init(ISecretKey^ key)
{$
	// ��� ����������� ������� �����������
	hMAC.Close(); if (paramsOID == ASN1::GOST::OID::hashes_cryptopro && 

		// ��� ������� ������������ �����
		(dynamic_cast<CAPI::CSP::SecretKey^>(key) != nullptr || key->Length == 32))
	{
		// ������� ������� �������
		CAPI::CSP::Mac::Init(key); return; 
	}
    // ��� ���������� �������� ����� ��������� ����������
    if (key->Value == nullptr) throw gcnew InvalidKeyException();

	// ������� �������� ���������� ������������
	hMAC.Attach(gcnew CAPI::MAC::HMAC(%hash)); hMAC.Get()->Init(key); 
}

