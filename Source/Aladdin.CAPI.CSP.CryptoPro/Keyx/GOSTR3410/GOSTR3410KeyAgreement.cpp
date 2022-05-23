#include "..\..\stdafx.h"
#include "GOSTR3410KeyAgreement.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOSTR3410KeyAgreement.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� ���� � 34.10-2001, 2012
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::Keyx::GOSTR3410::KeyAgreement::SetKeyParameters(
    CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey, array<BYTE>^ random, int keySize)
{$
    // ��������� ���������� ����� ���������� �����
    hKey->SetParam(KP_IV, random, 0); 

    // ������� ������������� ���������
    if (keySize == 32) hKey->SetLong(KP_ALGID, CALG_G28147       , 0); else 
    if (keySize == 64) hKey->SetLong(KP_ALGID, CALG_SYMMETRIC_512, 0); else 

	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException(); 
}
