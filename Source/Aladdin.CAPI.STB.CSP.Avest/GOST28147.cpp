#include "stdafx.h"
#include "GOST28147.h"
#include "Provider.h"

using namespace System::Runtime::InteropServices; 

///////////////////////////////////////////////////////////////////////////
// �������� ���������� ���� 28147-89
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::STB::Avest::CSP::GOST28147::BlockCipher::SetParameters(CAPI::CSP::KeyHandle hKey)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::GOST28147::BlockCipher::SetParameters); 	

	// �������� ������ ��� ������ ����������
	DWORD modeCSP = 0; switch (Mode)
	{
	// ������������ ����� ����������
	case CipherMode::CBC: modeCSP = CRYPT_MODE_CBC; break;
	case CipherMode::ECB: modeCSP = CRYPT_MODE_ECB; break;  
	case CipherMode::OFB: modeCSP = CRYPT_MODE_OFB; break;
	case CipherMode::CFB: modeCSP = CRYPT_MODE_CFB; break;
	}
	// ���������� ����� ����������
	CAPI::CSP::Handle::SetParam(hKey, KP_MODE, modeCSP, 0);  

	// ���������� �������������
	if (Mode != CipherMode::ECB) CAPI::CSP::Handle::SetParam(hKey, KP_IV, IV, 0);
}

///////////////////////////////////////////////////////////////////////////
// �������� ���������� ������������ ���� 28147-89
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::STB::Avest::CSP::GOST28147::Imito::SetParameters(CAPI::CSP::KeyHandle hKey) 
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::GOST28147::Imito::SetParameters); 	

	// ���������� ������� �����������
	CAPI::CSP::Handle::SetParam(hKey, KP_SUBST_BLOCK_OID, sboxOID, 0); 
}

