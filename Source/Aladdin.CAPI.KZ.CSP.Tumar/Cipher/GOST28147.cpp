#include "..\stdafx.h"
#include "GOST28147.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST28147.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� ���� 28147-89
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Cipher^ 
Aladdin::CAPI::KZ::CSP::Tumar::Cipher::GOST28147::CreateBlockMode(CipherMode^ mode)
{$
	// ��� ������ ECB
	if (dynamic_cast<CipherMode::ECB^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::Any); 
	}
	// ��� ������ CBC
	else if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::Any); 
	}
	// ��� ������ CFB
	else if (dynamic_cast<CipherMode::CFB^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// ��� ������ OFB
	else if (dynamic_cast<CipherMode::OFB^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// ��� ������ CTR
	else if (dynamic_cast<CipherMode::CTR^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException(); 
}

void Aladdin::CAPI::KZ::CSP::Tumar::Cipher::GOST28147::SetParameters(
	CAPI::CSP::KeyHandle^ hKey)
{$
	// ���������� ������� ����������� � ����� ����� �����
	hKey->SetString(KP_CIPHEROID, sboxOID, 0); 

	// ���������� ����� ����� �����
	hKey->SetLong(KP_MESHING, meshing ? 1 : 0, 0);
}


///////////////////////////////////////////////////////////////////////////
// ����� ���������� ���� 28147-89
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::KZ::CSP::Tumar::Cipher::GOST28147::BlockMode::SetParameters(
	CAPI::CSP::KeyHandle^ hKey, PaddingMode padding)
{$
	// ������� ������� �������
	CAPI::CSP::BlockMode::SetParameters(hKey, padding); 

	// ��� ������ CTR
	if (dynamic_cast<CipherMode::CTR^>(Mode) != nullptr)
	{
		// �������� ��������� ���������
		CipherMode::CTR^ parameters = (CipherMode::CTR^)Mode; 

		// ���������� ����� ����������
		hKey->SetLong(KP_MODE, CRYPT_MODE_CNT, 0);  

		// ���������� �������������
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
}
