#include "..\stdafx.h"
#include "..\Provider.h"
#include "GOSTR3410PrivateKey.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOSTR3410PrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������ ���� ���� P34.10
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::GOST::CSP::CryptoPro::GOSTR3410::PrivateKey::GetPrivateValue()
{$
    // ������������� ��� ����������
    Provider^ provider = (Provider^)Factory; 

	// �������� ��������� ����������
	CAPI::CSP::ContextHandle^ hContext = provider->Handle; 

	// �������� ��������� ����������
    if (Container != nullptr) hContext = ((CAPI::CSP::Container^)Container)->Handle;

	// �������� ��������� �����
	Using<CAPI::CSP::KeyHandle^> hKeyPair(OpenHandle()); 

	// ���������� ������������� ��������� �����
	ALG_ID algID = (ALG_ID)hKeyPair.Get()->GetLong(KP_ALGID, 0); 

	// ������������� ��������� �������� �����
	ALG_ID exportID = provider->GetExportID(provider->ConvertKeyOID(algID)); 

	// ������������� ���� ���������� �����
	Using<CAPI::CSP::KeyHandle^> hKEK(hContext->GenerateKey(CALG_G28147, CRYPT_EXPORTABLE)); 

	// �������� ������������� ������� �����������
	String^ sboxOID = hKEK.Get()->GetString(KP_CIPHEROID, 0);

	// ������� ������������� ���������
	hKEK.Get()->SetLong(KP_ALGID, exportID, 0); 

	// �������������� ������ ����
	array<BYTE>^ blob = Export(hKEK.Get(), 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	CRYPT_PUBKEY_INFO_HEADER* pBlob = (CRYPT_PUBKEY_INFO_HEADER*)(PBYTE)ptrBlob;

	// ������������ ������������� ���������
	hKEK.Get()->SetLong(KP_ALGID, CALG_G28147, 0); 

	// ���������� ������ �������������� ���������
	DWORD cbKeyTransfer = blob->Length - sizeof(*pBlob);

	// ������������� ��������� � �������������
	ASN1::GOST::CryptoProKeyTransfer^ keyTransfer = 
		gcnew ASN1::GOST::CryptoProKeyTransfer(
			ASN1::Encodable::Decode(blob, sizeof(*pBlob), cbKeyTransfer)
	); 
	// ������� �������� �������������� ������� �����
	ASN1::GOST::EncryptedKey^ encryptedKey = 
		keyTransfer->KeyTransferContent->EncryptedPrivateKey; 

	// ������� �������� UKM
	array<BYTE>^ ukm = keyTransfer->KeyTransferContent->SeanceVector->Value;

	// �������� ����� �����
	array<BYTE>^ wrappedCEK = Arrays::Concat(
		encryptedKey->Encrypted->Value, encryptedKey->MacKey->Value
	); 
	// ������� �������� ���������� �����
	Using<KeyWrap^> keyWrap(provider->CreateExportKeyWrap(hContext, exportID, sboxOID, ukm)); 

	// ������� ������ �����
	CAPI::CSP::SecretKey KEK(provider, Keys::GOST::Instance, hKEK.Get()); 

	// ������� ��� �����
	CAPI::SecretKeyFactory^ typeCEK = (wrappedCEK->Length == 36) ? 
		Keys::GOST::Instance : SecretKeyFactory::Generic; 

	// ������������ �������� �����
	Using<ISecretKey^> secret(keyWrap.Get()->Unwrap(%KEK, wrappedCEK, typeCEK));
		
	// ������������� ��������
	d = Math::Convert::ToBigInteger(secret.Get()->Value, Endian); 
}

