#include "stdafx.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Container.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::CryptoPro::Container::GenerateKeyPair(
	IntPtr hwnd, ALG_ID keyType, DWORD flags)
{$
    // ��� ������� ������������ ������ ������� ������� �������
    if ((Mode & CRYPT_SILENT) == 0) return CAPI::CSP::Container::GenerateKeyPair(hwnd, keyType, flags); 

	// ���������� ������������� ���������
	DWORD curveID = (keyType == AT_KEYEXCHANGE) ? PP_DHOID : PP_SIGNATUREOID; 
	
	// �������� ��������� ������������� ������
	String^ curveOID = Handle->GetString(curveID, 0); 

    // ��� ������� ���������� �����������
    String^ hashOID = nullptr; if (Provider->Type == PROV_GOST_2001_DH)
    {
        // �������� ��������� �����������
        hashOID  = Handle->GetString(PP_HASHOID, 0); 
    }
	// ������� ��������� � ����������� �����������
	Synchronize(); DetachHandle(); AttachHandle(Mode & ~CRYPT_SILENT);
	try { 
		// ������� ��������� ������������� ������
		Handle->SetString(curveID, curveOID, 0); 

		// ������� ��������� �����������
		if (hashOID != nullptr) Handle->SetString(PP_HASHOID, hashOID, 0); 

		// ������������� ���v�
		CAPI::CSP::Handle::Release(CAPI::CSP::Container::GenerateKeyPair(hwnd, keyType, flags)); 
	}
	// ������� ���������
	finally { DetachHandle(); }
	
	// ������� ��������� � �������� ��������� �����
	AttachHandle(Mode | CRYPT_SILENT); return Handle->GetUserKey(keyType);
} 

