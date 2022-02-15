#include "..\..\stdafx.h"
#include "GOST34310TransportKeyUnwrap.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310TransportKeyUnwrap.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ���������� �����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::KZ::CSP::Tumar::Keyx::GOST34310::TransportKeyUnwrap::Unwrap(
	IPrivateKey^ privateKey, TransportKeyData^ transportData, SecretKeyFactory^ keyFactory)
{$
	// ��������� ������� ����������
	if (transportData == nullptr) throw gcnew ArgumentException(); 

	// ������� ������������� ����
	array<BYTE>^ encryptedKey = transportData->EncryptedKey; 

	// ��������� ������ ������
	if (encryptedKey->Length < 12) throw gcnew InvalidDataException(); 

	// ��������� ������������ ���������
	if (encryptedKey[0] != SIMPLEBLOB || encryptedKey[1] != CUR_BLOB_VERSION) 
	{
		// ��� ������ ��������� ����������
		throw gcnew InvalidDataException();
	}
	// ������� ���������
	encryptedKey = Arrays::CopyOf(encryptedKey, 12, encryptedKey->Length - 12); 

	// ������������ ����� ������
	transportData = gcnew TransportKeyData(transportData->Algorithm, encryptedKey); 

	// ������������ ����
	return CAPI::CSP::TransportKeyUnwrap::Unwrap(privateKey, transportData, keyFactory); 
}
