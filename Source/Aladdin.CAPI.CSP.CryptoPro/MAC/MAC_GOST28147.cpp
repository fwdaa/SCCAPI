#include "..\stdafx.h"
#include "MAC_GOST28147.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "MAC_GOST28147.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ���������� ������������ ���� 28147-89
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::MAC::GOST28147::SetParameters(
	CAPI::CSP::KeyHandle^ hKey) 
{$
    // ������� ������� �������
    CAPI::CSP::Mac::SetParameters(hKey); 

	// ���������� ������� �����������
	hKey->SetString(KP_CIPHEROID, sboxOID, 0); 

	// ������������ ����� ����� �����
	if (meshing == ASN1::GOST::OID::keyMeshing_none)
	{
		// ���������� ����� ����� �����
		hKey->SetLong(KP_MIXMODE, CRYPT_SIMPLEMIX_MODE, 0); 
	}
	else if (meshing == ASN1::GOST::OID::keyMeshing_cryptopro)
	{
		// ���������� ����� ����� �����
		hKey->SetLong(KP_MIXMODE, CRYPT_PROMIX_MODE, 0); 
	}
	// ��� ������ ��������� ����������
	else throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CSP::HashHandle^ 
Aladdin::CAPI::CSP::CryptoPro::MAC::GOST28147::Construct(
	CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) 
{$
	// ������� �������� ���������� �����������
	Using<CAPI::CSP::HashHandle^> hHash(CAPI::CSP::Mac::Construct(hContext, hKey)); 

	// ���������� ��������� ��������
	hHash.Get()->SetParam(HP_HASHSTARTVECT, start, 0); return hHash.Detach();
}

