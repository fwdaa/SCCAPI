#include "..\stdafx.h"
#include "GOST28147.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST28147.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������� �������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Cipher^ 
Aladdin::CAPI::CSP::CryptoPro::Cipher::GOST28147::CreateBlockMode(CipherMode^ mode)
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
	// ��� ������ CTR
	else if (dynamic_cast<CipherMode::CTR^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException(); 
}

void Aladdin::CAPI::CSP::CryptoPro::Cipher::GOST28147::SetParameters(
	CAPI::CSP::KeyHandle^ hKey)
{$
	// ���������� ������� �����������
	hKey->SetString(KP_CIPHEROID, sboxOID, 0);

	// � ����������� �� ������ ����� �����
	if (meshing == ASN1::GOST::OID::keyMeshing_none)
	{
		// ���������� ����� ����� �����
		hKey->SetLong(KP_MIXMODE, CRYPT_SIMPLEMIX_MODE, 0);  
	}
	// � ����������� �� ������ ����� �����
	else if (meshing == ASN1::GOST::OID::keyMeshing_cryptopro)
	{
		// ���������� ����� ����� �����
		hKey->SetLong(KP_MIXMODE, CRYPT_PROMIX_MODE, 0);  
	}
	// ��� ������ ��������� ����������
	else throw gcnew NotSupportedException(); 
}

///////////////////////////////////////////////////////////////////////////
// ����� �������� ��������� ����������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::Cipher::GOST28147::BlockMode::SetParameters(
	CAPI::CSP::KeyHandle^ hKey, PaddingMode padding)
{$
	// ������� ������� �������
	CAPI::CSP::BlockMode::SetParameters(hKey, padding);

	// ��� ������ CBC
	if (dynamic_cast<CipherMode::CBC^>(Mode) != nullptr)
	{
		// �������� ��������� ���������
		CipherMode::CBC^ parameters = (CipherMode::CBC^)Mode; 

		// ���������� ����� ����������
		hKey->SetLong(KP_MODE, CRYPT_MODE_CBCRFC4357, 0);  

		// ���������� �������������
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
	// ��� ������ CTR
	else if (dynamic_cast<CipherMode::CTR^>(Mode) != nullptr)
	{
		// �������� ��������� ���������
		CipherMode::CTR^ parameters = (CipherMode::CTR^)Mode; 

		// ���������� ����� ����������
		hKey->SetLong(KP_MODE, CRYPT_MODE_CNT, 0);  

		// ���������� �������������
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
}

