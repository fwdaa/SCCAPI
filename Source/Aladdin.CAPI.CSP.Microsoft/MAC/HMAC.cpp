#include "..\stdafx.h"
#include "HMAC.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "HMAC.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������������ HMAC
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ 
Aladdin::CAPI::CSP::Microsoft::MAC::HMAC::Construct(
	CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) 
{$
	// ������� �������� ���������� �����������
	Using<CAPI::CSP::HashHandle^> hHash(CAPI::CSP::Mac::Construct(hContext, hKey)); 

	// ������� ������������� ��������� �����������
	HMAC_INFO info = { hashAlgorithm->AlgID, nullptr, 0, nullptr, 0 }; 

	// ���������� ������������� ��������� �����������
	hHash.Get()->SetParam(HP_HMAC_INFO, IntPtr(&info), 0); return hHash.Detach();
} 
