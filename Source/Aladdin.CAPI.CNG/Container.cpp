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
Aladdin::CAPI::CNG::Container::Container(ProviderStore^ store, 
	String^ name, DWORD mode) : CAPI::Container(store, name)
{$
	// ������� ������ ��� ����������
	String^ nativeName = store->GetNativeContainerName(name); 

	// ������� ����� ��������
	this->mode = mode | NCRYPT_SILENT_FLAG; keyType = 0; 
	
	// ��� ���� ������
	for (DWORD type = AT_KEYEXCHANGE; type <= AT_SIGNATURE; type++)
	{
		// �������� ��������� �������� ����
		hKeyPair.Attach(Provider->Handle->OpenKey(nativeName, type, this->mode)); 

		// ��������� ������� �����
		if (hKeyPair.Get() != nullptr) { keyType = type; break; }
	}
}

Aladdin::CAPI::CNG::Container::~Container() { $ }

///////////////////////////////////////////////////////////////////////
// ������� ������������� ��������������
///////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CNG::Container::IsAuthenticationRequired(Exception^ e)
{$
	// ��������� ����� ��������
	if ((mode & NCRYPT_SILENT_FLAG) == 0) return false; 

	// ������� ������� ����������
	return Store->IsAuthenticationRequired(e); 
}

///////////////////////////////////////////////////////////////////////
// �������� � ������ ������ ����������
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Container::CompleteGenerateKeyPair(
	IntPtr hwnd, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags)
{
	// ��������� �������������� ��������
	if (action != nullptr) action(hKeyPair.Get()); if (exportable)
	{ 
		// ������� ��� ���������
		String^ paramName = gcnew String(NCRYPT_EXPORT_POLICY_PROPERTY); 

		// ������� ������ ��������
		DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG; 

		// ������� ������� ����������� ���������
		DWORD persistFlags = NCRYPT_SILENT_FLAG | NCRYPT_PERSIST_FLAG; 

		// ������� ������������ �������� �����
		hKeyPair.Get()->SetParam(paramName, IntPtr(&policy), sizeof(policy), persistFlags); 
	}
	// ��� �������� ��������� ����
	if ((mode & NCRYPT_SILENT_FLAG) != 0 || hwnd == IntPtr::Zero) 
	{
		// ��������� �������� �������� ����
		hKeyPair.Get()->Finalize(flags);
	}
	else { 
		// ������� ��������� ����
		hKeyPair.Get()->SetParam(NCRYPT_WINDOW_HANDLE_PROPERTY, IntPtr(&hwnd), hwnd.Size, 0); 
		try { 
			// ��������� �������� �������� ����
			hKeyPair.Get()->Finalize(flags); hwnd = IntPtr::Zero; 
		}
		// �������� ��������� ����
		finally { hKeyPair.Get()->SetParam(NCRYPT_WINDOW_HANDLE_PROPERTY, IntPtr(&hwnd), hwnd.Size, 0); }
	}
}

Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::CNG::Container::GenerateKeyPair(IntPtr hwnd, 
	String^ alg, DWORD keyType, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags)
{$
	if (hKeyPair.Get() != nullptr)
	{
		// ��������� ���������� ����
		if (this->keyType != keyType) throw gcnew Win32Exception(NTE_BAD_TYPE);
			
		// ������� ����
		else DeleteKeyPair(gcnew array<BYTE> { (BYTE)keyType }); 
	}
	// ���������� ����� �������� �����
	DWORD createFlags = flags & NCRYPT_OVERWRITE_KEY_FLAG;

	// ���������� ����� ���������� �������� �����
	DWORD finalizeFlags = (flags & ~createFlags) | NCRYPT_SILENT_FLAG; 

	// ������� ������ ��� ����������
	String^ nativeName = Store->GetNativeContainerName(Name->ToString()); 

   	// ������� ����
    hKeyPair.Attach(Provider->Handle->StartCreateKey(
		nativeName, alg, keyType, (mode & ~NCRYPT_SILENT_FLAG) | createFlags
	));
	try { 
		// ������� ������
		Container^ container = (Container^)Proxy::SecurityObjectProxy::Create(this); 

		// ���������� ��������� �������� ����
		container->CompleteGenerateKeyPair(hwnd, exportable, action, finalizeFlags); 

		// ���������� ��� �����
		this->keyType = keyType; return hKeyPair.Get(); 
	}
	// ���������� ��������� ������
	catch (Exception^) { hKeyPair.Close(); throw; } 
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::Container::ImportKeyPair(
	IntPtr hwnd, NKeyHandle^ hImportKey, DWORD keyType, String^ typeBlob, 
	IntPtr ptrBlob, DWORD cbBlob, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags)
{$
	if (hKeyPair.Get() != nullptr)
	{
		// ��������� ���������� ����
		if (this->keyType != keyType) throw gcnew Win32Exception(NTE_BAD_TYPE);
			
		// ������� ����
		else DeleteKeyPair(gcnew array<BYTE> { (BYTE)keyType }); 
	}
	// ���������� ����� �������� �����
	DWORD importFlags = flags & NCRYPT_OVERWRITE_KEY_FLAG;

	// ���������� ����� ���������� �������� �����
	DWORD finalizeFlags = (flags & ~importFlags) | NCRYPT_SILENT_FLAG; 

	// ������� ������ ��� ����������
	String^ nativeName = Store->GetNativeContainerName(Name->ToString()); 

   	// ������������� ����
    hKeyPair.Attach(Provider->Handle->StartImportKeyPair(nativeName, 
		hImportKey, typeBlob, ptrBlob, cbBlob, (mode & ~NCRYPT_SILENT_FLAG) | importFlags
	));
	try { 
		// ������� ������
		Container^ container = (Container^)Proxy::SecurityObjectProxy::Create(this); 

		// ���������� ��������� �������� ����
		container->CompleteGenerateKeyPair(hwnd, exportable, action, finalizeFlags); 

		// ���������� ��� �����
		this->keyType = keyType; return hKeyPair.Get(); 
	}
	// ���������� ��������� ����������
	catch (Exception^) { hKeyPair.Close(); throw; } 
}

array<BYTE>^ Aladdin::CAPI::CNG::Container::ExportKey(
    NKeyHandle^ hKey, NKeyHandle^ hExportKey, String^ blobType, DWORD flags)
{$
	// ������� ����� �������
	flags |= (mode & NCRYPT_SILENT_FLAG); 

    // ���������� ������ ������
    DWORD cbBlob = hKey->Export(hExportKey, blobType, flags, IntPtr::Zero, 0); 

	// �������� ������ ��� ��������� ��������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// �������������� ����
	cbBlob = hKey->Export(hExportKey, blobType, flags, IntPtr(ptrBlob), cbBlob);

	// �������� ������ ������
	Array::Resize(blob, cbBlob); return blob; 
}

Aladdin::CAPI::CNG::NSecretHandle^ 
Aladdin::CAPI::CNG::Container::AgreementSecret(
	NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey, DWORD flags)
{$
	// ������� ����� �������
	flags |= (mode & NCRYPT_SILENT_FLAG); 

	// ��������� ������������ �����
	return hPrivateKey->AgreementSecret(hPublicKey, flags); 
}

array<BYTE>^ Aladdin::CAPI::CNG::Container::Decrypt(
	NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// ������� ����� �������
	flags |= (mode & NCRYPT_SILENT_FLAG); 

	// ������������ ������
	return hPrivateKey->Decrypt(padding, data, flags); 
}

array<BYTE>^ Aladdin::CAPI::CNG::Container::SignHash(
	NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ hash, DWORD flags) 
{$
	// ������� ����� �������
	flags |= (mode & NCRYPT_SILENT_FLAG); 

	// ��������� ���-��������
	return hPrivateKey->SignHash(padding, hash, flags); 
}

///////////////////////////////////////////////////////////////////////
// ���������� ������� ����������
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Container::GetKeyID(KeyUsage keyUsage)
{$
	KeyUsage signMask = KeyUsage::DigitalSignature | KeyUsage::CertificateSignature | 
		                KeyUsage::CrlSignature     | KeyUsage::NonRepudiation; 
	KeyUsage keyxMask = KeyUsage::KeyEncipherment  | KeyUsage::KeyAgreement; 
	
	if (hKeyPair.Get() == nullptr) 
	{
		// ������� ������������� �����
		array<BYTE>^ keyID = gcnew array<BYTE> { AT_KEYEXCHANGE }; 

		// ������� �������������
		if ((keyUsage & signMask) != KeyUsage::None) keyID[0] = AT_SIGNATURE; 
		if ((keyUsage & keyxMask) != KeyUsage::None) keyID[0] = AT_KEYEXCHANGE; return keyID; 
	}
	else { KeyUsage decodedUsage = KeyUsage::None;

		// ��������������� ������ �������������
		if ((keyUsage & keyxMask) != KeyUsage::None) keyUsage = keyUsage | keyxMask; 
		if ((keyUsage & signMask) != KeyUsage::None) keyUsage = keyUsage | signMask; 

		// ������� ������������� �����
		array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

		// ������� ������������� ����� �� ���������
		if (keyType == AT_KEYEXCHANGE) decodedUsage = decodedUsage | keyxMask; 
		if (keyType == AT_SIGNATURE  ) decodedUsage = decodedUsage | signMask; 

		// �������� ����������
		Certificate^ certificate = GetCertificate(keyID);

		// ��������� ������� �����������
		if (certificate != nullptr) { decodedUsage = decodedUsage | certificate->KeyUsage; 

			// ������� �������������� ����
			decodedUsage = decodedUsage & (signMask | keyxMask); 
			
			// ��������� ���������� ������� �������������
			if ((decodedUsage & keyUsage) != decodedUsage) keyID = nullptr;
		}
		return keyID; 
	}
}

array<array<BYTE>^>^ Aladdin::CAPI::CNG::Container::GetKeyIDs()
{$
	// ��������� ������� ���������������
	if (keyType == 0) return gcnew array<array<BYTE>^>(0); 

	// ������� ������������� �����
	array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

	// ������� �������������
	return gcnew array<array<BYTE>^> { keyID }; 
}

array<array<BYTE>^>^ Aladdin::CAPI::CNG::Container::GetKeyIDs(
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ keyInfo)
{$
	// ��������� ������� �����
	if (hKeyPair.Get() == nullptr) return gcnew array<array<BYTE>^>(0); 

	// ������� ������ ���������������
	List<array<BYTE>^>^ keyIDs = gcnew List<array<BYTE>^>(); 

	// ������� �������������
	array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType };
	
	// �������� ����������
	Certificate^ other = GetCertificate(keyID); if (other != nullptr)
	{
		// ��������� ������ �������������
		if (other->PublicKeyInfo->Equals(keyInfo)) keyIDs->Add(keyID);
	}
	else {
		// �������� ���������� �� �������� �����
		ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
			Provider->ExportPublicKey(hKeyPair.Get()); 

		// ��������� ���������� ������
		if (publicKeyInfo->Equals(keyInfo)) keyIDs->Add(keyID); 
	}
	return keyIDs->ToArray(); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::CNG::Container::GetPublicKeyInfo(array<BYTE>^ keyID)
{$
	// ��������� ������� �����
	if (hKeyPair.Get() == nullptr || keyType != keyID[0]) 
	{
		// ��� ������ ��������� ����������
		throw gcnew Win32Exception(NTE_NO_KEY); 
	}
	// �������� ���������� �� �������� �����
	return Provider->ExportPublicKey(hKeyPair.Get()); 
}

Aladdin::CAPI::IPublicKey^ 
Aladdin::CAPI::CNG::Container::GetPublicKey(array<BYTE>^ keyType)
{$
    // �������� �������� ����
    ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = GetPublicKeyInfo(keyType); 

    // ��������� ������� ��������� �����
    if (publicKeyInfo == nullptr) return nullptr; 

    // ������������� �������� ����
    return Provider->DecodePublicKey(publicKeyInfo); 
}

Aladdin::CAPI::IPrivateKey^ Aladdin::CAPI::CNG::Container::GetPrivateKey(array<BYTE>^ keyID)
{$
	// ��������� ������� �����
	if (hKeyPair.Get() == nullptr) throw gcnew Win32Exception(NTE_NO_KEY);

	// �������� ���������� �� �������� �����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ keyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// ������������� �������� ����
	IPublicKey^ publicKey = Provider->DecodePublicKey(keyInfo);
 
	// ������� ������ ���� 
	return Provider->GetPrivateKey(this, publicKey, hKeyPair.Get()); 
}

///////////////////////////////////////////////////////////////////////
// ���������� �������������
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CNG::Container::GetCertificate(array<BYTE>^ keyID)
{$
	// ��������� ������� ����������
	if (keyID == nullptr) throw gcnew ArgumentException(); 

	// ��������� ������� �����
	if (hKeyPair.Get() == nullptr || keyType != keyID[0]) return nullptr; 

	// �������� p�������������� �������� ����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// �������� ����������
	return Store->GetCertificate(hKeyPair.Get(), publicKeyInfo); 
}

void Aladdin::CAPI::CNG::Container::SetCertificate(
	array<BYTE>^ keyID, Certificate^ certificate)
{$
	// ��������� ������� ����������
	if (keyID == nullptr) throw gcnew ArgumentException(); 

	// ��������� ������� �����
	if (hKeyPair.Get() == nullptr || keyType != keyID[0]) gcnew Win32Exception(NTE_NO_KEY); 

	// ��������� ���������� � ���������
	Store->SetCertificate(hKeyPair.Get(), certificate); 
}

array<BYTE>^ Aladdin::CAPI::CNG::Container::SetKeyPair(
	IRand^ rand, KeyPair^ keyPair, KeyUsage keyUsage, KeyFlags keyFlags)
{$
	// ��������� ������� ����������
	if (keyPair == nullptr) throw gcnew ArgumentException(); 

	// �������� ������������� �����
	array<BYTE>^ keyID = keyPair->KeyID; if (keyID != nullptr)
	{
		// ��������� ������������ ��������������
		if (keyID->Length != 1) throw gcnew Win32Exception(NTE_BAD_UID);
	}
	// ������� ������������� ����� 
	else keyID = GetKeyID(keyUsage); 
    
    // ��� ������ ��������� ����������
    if (keyID == nullptr) throw gcnew Win32Exception(NTE_NO_MORE_ITEMS);

    // ������� ������� ����������������
    BOOL exportable = ((keyFlags & KeyFlags::Exportable) != KeyFlags::None);

	// ��� �������� ������������� ����
	IntPtr hwnd = IntPtr::Zero; if (rand->Window != nullptr)
	{
		// ������� ��������� ����
		hwnd = ((IWin32Window^)rand->Window)->Handle; 
	}
	// ������������� ���� � ���������
	Provider->ImportKeyPair(this, hwnd, 
		keyID[0], exportable, keyPair->PublicKey, keyPair->PrivateKey
	); 
	return keyID;
}

void Aladdin::CAPI::CNG::Container::DeleteKeyPair(array<BYTE>^ keyID)
{$
	// ��������� ������� ����������
	if (keyID == nullptr) throw gcnew ArgumentException(); 

	// ��������� ������� �����
	if (hKeyPair.Get() == nullptr || keyType != keyID[0])
	{
		// ��� ������ ��������� ����������
		throw gcnew Win32Exception(NTE_NO_KEY);
	}
	DeleteKeys(); 
}

void Aladdin::CAPI::CNG::Container::DeleteKeys()
{$
	// ��������� ������� ������
	if (hKeyPair.Get() == nullptr) return;
	try {
		// ������� ���� ������ (���� ��� ������ ��������� ������������)
		Provider->Handle->DeleteKey(hKeyPair.Get(), mode); 
		
		// �������� ���������
		hKeyPair.Attach(nullptr); keyType = 0;
	}
	// ��� ������ ������������ ���������
	catch (Exception^) { hKeyPair.Attach(nullptr); 
	 
		// ������� ������ ��� ����������
		String^ nativeName = Store->GetNativeContainerName(Name->ToString()); 
		try { 
			// �������� ��������� �������� ����
			hKeyPair.Attach(Provider->Handle->OpenKey(nativeName, keyType, mode));
		}
		// ���������� ��������� ������
		catch (Exception^) { keyType = 0; } throw; 
    }
}
