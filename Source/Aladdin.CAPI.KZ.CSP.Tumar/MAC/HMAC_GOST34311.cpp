#include "..\stdafx.h"
#include "HMAC_GOST34311.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "HMAC_GOST34311.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� HMAC ���� � 34.11-1994
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::KZ::CSP::Tumar::MAC::HMAC_GOST34311::Init(ISecretKey^ key)
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
