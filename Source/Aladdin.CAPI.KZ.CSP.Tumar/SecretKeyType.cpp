#include "stdafx.h"
#include "SecretKeyType.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "SecretKeyType.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��� ����� ����������
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::KZ::CSP::Tumar::SecretKeyType::ConstructKey(
	CAPI::CSP::ContextHandle^ hContext, array<BYTE>^ value, DWORD flags)
{$
	// ������� ������� �������
	Using<CAPI::CSP::KeyHandle^> hKey(CAPI::ANSI::CSP::Microsoft::SecretKeyType::ConstructKey(hContext, value, flags)); 

	// ���������� ������� �������������
	BYTE iv[16] = {0}; hKey.Get()->SetParam(KP_IV, IntPtr(iv), 0); return hKey.Detach();
}

array<BYTE>^ Aladdin::CAPI::KZ::CSP::Tumar::SecretKeyType::GetKeyValue(
	CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hCEK)
{$
	// ������� ����
	Using<CAPI::CSP::KeyHandle^> hKEK(hContext->GenerateKey(CALG_GOST, 0)); 

	// ���������� ��������� ������ ������ ��� ��������
	DWORD cbBlob = hCEK->Export(hKEK.Get(), SIMPLEBLOB, 0, IntPtr::Zero, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// �������������� ����
	cbBlob = hCEK->Export(hKEK.Get(), SIMPLEBLOB, 0, IntPtr(ptrBlob), cbBlob);

	// ������������� ������������� ����
	ASN1::KZ::EncryptedKey^ encryptedKey = gcnew ASN1::KZ::EncryptedKey(
		ASN1::Encodable::Decode(blob, 12, cbBlob - 12)
	); 
	// ������� ���� �� ���������
	array<BYTE>^ spc = encryptedKey->Spc      ->Value; 
	array<BYTE>^ enc = encryptedKey->Encrypted->Value; 

	// ���������� ������������� ������
	array<BYTE>^ data = Arrays::Concat(spc, enc); 

	// ������������ ������������� ������
	hKEK.Get()->Decrypt(data, 0, data->Length, FALSE, 0, data, 0);
		
	// ������� �������� �������������� �����
	return Arrays::CopyOf(data, spc->Length, enc->Length); 
}

