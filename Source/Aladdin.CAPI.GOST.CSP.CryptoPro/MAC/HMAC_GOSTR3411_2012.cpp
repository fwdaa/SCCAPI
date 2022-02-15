#include "..\stdafx.h"
#include "HMAC_GOSTR3411_2012.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "HMAC_GOSTR3411_2012.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� HMAC ���� � 34.11-2012
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::GOST::CSP::CryptoPro::MAC::HMAC_GOSTR3411_2012::Init(ISecretKey^ key)
{$
	// ��� ������� ������������ �����
	hMAC.Close(); if (dynamic_cast<CAPI::CSP::SecretKey^>(key) != nullptr || key->Length == 32)
	{
		// ������� ������� �������
		CAPI::CSP::Mac::Init(key); return; 
	}
    // ��� ���������� �������� ����� ��������� ����������
    if (key->Value == nullptr) throw gcnew InvalidKeyException();

	// ������� �������� ���������� ������������
	hMAC.Attach(gcnew CAPI::MAC::HMAC(%hash)); hMAC.Get()->Init(key); 
}
