#include "stdafx.h"
#include "Generator.h"
#include "Provider.h"
#include "Key.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Generator.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
//////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ 
Aladdin::CAPI::CNG::NKeyPairGenerator::Generate(String^ keyOID, KeyUsage keyUsage)
{$
	DWORD keyID = AT_KEYEXCHANGE; 

	KeyUsage signMask = KeyUsage::DigitalSignature | KeyUsage::CertificateSignature | 
		                KeyUsage::CrlSignature     | KeyUsage::NonRepudiation; 
	KeyUsage keyxMask = KeyUsage::KeyEncipherment  | KeyUsage::KeyAgreement; 

	// ������� �������������
	if ((keyUsage & signMask) != KeyUsage::None) keyID = AT_SIGNATURE; 
	if ((keyUsage & keyxMask) != KeyUsage::None) keyID = AT_KEYEXCHANGE; 

	// ������������� ���� ������
	Using<NKeyHandle^> hKeyPair(Generate(nullptr, keyOID, keyID, TRUE));

	// �������������� �������� ����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
        Provider->ExportPublicKey(hKeyPair.Get()); 

    // ������������� �������� ����
    CAPI::IPublicKey^ publicKey = Provider->DecodePublicKey(publicKeyInfo);
 
	// �������� ������ ����
	Using<IPrivateKey^> privateKey(Provider->GetPrivateKey(Scope, publicKey, hKeyPair.Get())); 

    // ������� ��������� ���� ������
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr);  
}

Aladdin::CAPI::KeyPair^ Aladdin::CAPI::CNG::NKeyPairGenerator::Generate(
	array<BYTE>^ keyID, String^ keyOID, KeyUsage keyUsage, KeyFlags keyFlags)
{$
    // ��������� �������� ����������
    if (dynamic_cast<Container^>(Scope) == nullptr) return Generate(keyOID, keyUsage); 

	// ������������� ��� ����������
	Container^ container = (Container^)Scope; if (keyID != nullptr)
	{
		// ��������� ������������ ��������������
		if (keyID->Length != 1) throw gcnew Win32Exception(NTE_BAD_UID);
	}
	// ������� ������������� ����� 
	else keyID = container->GetKeyID(keyUsage); 
    
    // ��� ������ ��������� ����������
    if (keyID == nullptr) throw gcnew Win32Exception(NTE_NO_MORE_ITEMS);

    // ������� ������� ����������������
    BOOL exportable = ((keyFlags & KeyFlags::Exportable) != KeyFlags::None);  

	// ������������� ���� ������
	Using<NKeyHandle^> hKeyPair(Generate(container, keyOID, keyID[0], exportable));

    // �������� �������� ����
    CAPI::IPublicKey^ publicKey = container->GetPublicKey(keyID);

    // �������� ������ ���� 
	Using<CAPI::IPrivateKey^> privateKey(container->GetPrivateKey(keyID)); 

    // ������� ��������� ���� ������
    return gcnew KeyPair(publicKey, privateKey.Get(), keyID);  
}

Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::CNG::NKeyPairGenerator::Generate(Container^ container, String^ alg, 
	DWORD keyType, BOOL exportable, Action<Handle^>^ action, DWORD flags)
{$
	// ��� �������� ������������� ����
	IntPtr hwnd = IntPtr::Zero; if (Rand->Window != nullptr)
	{
		// ������� ��������� ����
		hwnd = ((IWin32Window^)Rand->Window)->Handle; 
	}
    // ��������� ��������� ���� � ����������
    if (container != nullptr) return container->GenerateKeyPair(hwnd, alg, keyType, exportable, action, flags);  

	// ���������� ����� �������� �����
	DWORD createFlags = flags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG);

	// ���������� ����� ���������� �������� �����
	DWORD finalizeFlags = (flags & ~createFlags) | NCRYPT_SILENT_FLAG; 
	
	// ������� ����
	Using<NKeyHandle^> hKey(Provider->Handle->StartCreateKey(nullptr, alg, keyType, flags));

	// ��������� �������������� ���������
	if (action != nullptr) action(hKey.Get()); 
		
	// ������� ��� ���������
	if (exportable) { String^ paramName = NCRYPT_EXPORT_POLICY_PROPERTY; 

		// ������� ������ ��������
		DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG; 

		// ������� ������������ �������� �����
		hKey.Get()->SetParam(paramName, IntPtr(&policy), sizeof(policy), NCRYPT_SILENT_FLAG); 
	}
	// ��������� �������� �������� ����
	hKey.Get()->Finalize(finalizeFlags); return hKey.Detach();
}
