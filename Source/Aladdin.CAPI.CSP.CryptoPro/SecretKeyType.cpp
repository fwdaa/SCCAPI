#include "stdafx.h"
#include "SecretKeyType.h"
#include "Wrap\RFC4357.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "SecretKeyType.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��� ����� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::CryptoPro::SecretKeyType::ConstructKey(
    CAPI::CSP::ContextHandle^ hContext, array<BYTE>^ value, DWORD flags)
{$
	// ������������� ��������� ���� ��������/�������
	Using<CAPI::CSP::KeyHandle^> hKEK(
		hContext->GenerateKey(CALG_G28147, CRYPT_EXPORTABLE)
	); 
	// ���������� ��������� ��������� ����������
    hKEK.Get()->SetLong(KP_MODE   , CRYPT_MODE_ECB, 0); 
    hKEK.Get()->SetLong(KP_PADDING, ZERO_PADDING  , 0); 

    // ������� ������� �������������
    array<BYTE>^ ukm = gcnew array<BYTE>(SEANCE_VECTOR_LEN); 

	// ������� �������� ���������� �����������
	Using<CAPI::CSP::HashHandle^> hHash(hContext->CreateHash(
		CALG_G28147_MAC, hKEK.Get(), 0
	)); 
	// ���������� ��������� ��������
	hHash.Get()->SetParam(HP_HASHSTARTVECT, ukm, 0); 

	// ��������� ������������ �� �����
	hHash.Get()->HashData(value, 0, value->Length, 0);  

	// �������� ������������ �� �����
	array<BYTE>^ mac = hHash.Get()->GetParam(HP_HASHVAL, 0); 

	// �������� ������ ��� ����������
	array<BYTE>^ wrapped = gcnew array<BYTE>(value->Length + EXPORT_IMIT_SIZE); 

	// ����������� ���������� �����
	hKEK.Get()->Encrypt(value, 0, value->Length, TRUE, 0, wrapped, 0); 

	// ����������� ������������ �� �����
	Array::Copy(mac, 0, wrapped, value->Length, EXPORT_IMIT_SIZE);

	// ������������ ���� ���������� ������
	Using<CAPI::CSP::KeyHandle^> hCEK(Wrap::RFC4357::UnwrapKey(
		hContext, CALG_SIMPLE_EXPORT, ukm, hKEK.Get(), wrapped
	)); 
	// ���������� ������������� ��������� � ������� ��������� �����
	hCEK.Get()->SetLong(KP_ALGID, AlgID, 0); return hCEK.Detach();
}

array<BYTE>^ Aladdin::CAPI::CSP::CryptoPro::SecretKeyType::GetKeyValue(
    CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hCEK)
{$
	// ���������� ������ ����� � ������
	int keySize = hCEK->GetLong(KP_KEYLEN, 0) / 8; 

	// ������������� ��������� ���� ��������/�������
	Using<CAPI::CSP::KeyHandle^> hKEK(
		hContext->GenerateKey(CALG_G28147, CRYPT_EXPORTABLE)
	);
	// ������� ��������� ������
	array<BYTE>^ ukm = gcnew array<BYTE>(SEANCE_VECTOR_LEN); 

	// ����������� ���� ���������� ������
	array<BYTE>^ wrappedCEK = Wrap::RFC4357::WrapKey(
		CALG_SIMPLE_EXPORT, ukm, hKEK.Get(), hCEK
	); 
	// ��������� ������ �������������� �����
	if (wrappedCEK->Length != keySize + EXPORT_IMIT_SIZE) 
	{
		// ��� ������ ��������� ����������
		throw gcnew System::IO::InvalidDataException();
	}
	// ���������� ������������� ��������� �������������
	hKEK.Get()->SetLong(KP_ALGID, CALG_G28147, 0); 

	// ���������� ����� ��� ��������� ����������
	hKEK.Get()->SetLong(KP_MODE, CRYPT_MODE_ECB, 0); 

	// ���������� ������ ����������
	hKEK.Get()->SetLong(KP_PADDING, ZERO_PADDING, 0); 

    // �������� ������ ��� �����
    array<BYTE>^ value = gcnew array<BYTE>(keySize); 

	// ������������ ����
	hKEK.Get()->Decrypt(wrappedCEK, 0, keySize, TRUE, 0, value, 0); return value;
}

