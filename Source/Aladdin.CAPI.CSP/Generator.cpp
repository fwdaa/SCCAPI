#include "stdafx.h"
#include "Generator.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Generator.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
//////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ Aladdin::CAPI::CSP::KeyPairGenerator::Generate(String^ keyOID, KeyUsage keyUsage)
{$
	DWORD keyType = AT_KEYEXCHANGE;

	KeyUsage signMask = KeyUsage::DigitalSignature | KeyUsage::CertificateSignature | 
		                KeyUsage::CrlSignature     | KeyUsage::NonRepudiation; 
	KeyUsage keyxMask = KeyUsage::KeyEncipherment  | KeyUsage::KeyAgreement; 

	// ������� �������������
	if ((keyUsage & signMask) != KeyUsage::None) keyType = AT_SIGNATURE; 
	if ((keyUsage & keyxMask) != KeyUsage::None) keyType = AT_KEYEXCHANGE; 

	// ������������� ���� ������
	Using<KeyHandle^> hKeyPair(Generate(nullptr, keyOID, keyType, 0)); 

	// �������������� �������� ����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
        Provider->ExportPublicKey(hKeyPair.Get()); 

    // ������������� �������� ����
    CAPI::IPublicKey^ publicKey = Provider->DecodePublicKey(publicKeyInfo);
 
	// �������� ������ ����
	Using<IPrivateKey^> privateKey(Provider->GetPrivateKey(
		Scope, publicKey, hKeyPair.Get(), keyType
	)); 
    // ������� ��������� ���� ������
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr);  
}

Aladdin::CAPI::KeyPair^ Aladdin::CAPI::CSP::KeyPairGenerator::Generate(
	array<BYTE>^ keyID, String^ keyOID, KeyUsage keyUsage, KeyFlags keyFlags)
{$
    // ��������� �������� ����������
    if (dynamic_cast<Container^>(Scope) == nullptr) return Generate(keyOID, keyUsage);  

	// ������������� ��� ����������
	Container^ container = (Container^)Scope; 

	// ��� �������� ��������������
	DWORD keyType = 0; if (keyID != nullptr)
	{
		// ��������� ������������ ��������������
		if (keyID->Length != 1) throw gcnew Win32Exception(NTE_BAD_UID); keyType = keyID[0];
	}
	// ���������� ��� ����� 
	if (keyType == 0) keyType = container->GetKeyType(keyOID, keyUsage); 

	// ��� ������ ��������� ����������
	if (keyType == 0) throw gcnew Win32Exception(NTE_NO_MORE_ITEMS);

    // ������� ������� ����������������
    DWORD flags = ((keyFlags & KeyFlags::Exportable) != KeyFlags::None) ? CRYPT_EXPORTABLE : 0; 

	// ������������� ���� ������
	Using<KeyHandle^> hKeyPair(Generate(container, keyOID, keyType, flags)); 

	// �������������� �������� ����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// ������������� �������� ����
	IPublicKey^ publicKey = Provider->DecodePublicKey(publicKeyInfo);
 
	// �������� ������ ����
	Using<CSP::PrivateKey^> privateKey(Provider->GetPrivateKey(
		container, publicKey, hKeyPair.Get(), keyType
	)); 
	// ������� ��������� ���� ������
	return gcnew KeyPair(publicKey, privateKey.Get(), privateKey.Get()->KeyID);  
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::KeyPairGenerator::Generate(CSP::Container^ container, ALG_ID algID, DWORD flags)
{$
	// ������������� ��������� ����
	if (container == nullptr) return Provider->Handle->GenerateKey(algID, flags);

	// ��� �������� ������������� ����
	IntPtr hwnd = IntPtr::Zero; if (Rand->Window != nullptr)
	{
		// ������� ��������� ����
		hwnd = ((IWin32Window^)Rand->Window)->Handle; 
	}
	// ������������� ���� � ����������
	return container->GenerateKeyPair(hwnd, algID, flags);
}
