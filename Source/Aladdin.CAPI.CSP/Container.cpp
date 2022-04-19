#include "stdafx.h"
#include "Container.h"
#include "Rand.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Container.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IRand^ Aladdin::CAPI::CSP::Container::CreateRand(Object^ window)
{$ 
	// ��� �������� ������������� ����
	HWND hwnd = NULL; if (window != nullptr)
	{
		// ������� ��������� ����
		hwnd = (HWND)((IWin32Window^)window)->Handle.ToPointer(); 
	}
	// ��� ������� ���������� ������������
	if ((Mode & CRYPT_SILENT) == 0 && hwnd != NULL) 
	{
		// ������� ��������� ��������� ������
		return gcnew HardwareRand(Handle, window);
	}
	// ������� ��������� ��������� ������
	else return gcnew Rand(Handle, window);
}

///////////////////////////////////////////////////////////////////////
// �������� � ���������� ����������
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Container::AttachHandle(String^ nativeName, DWORD mode)
{$
	// ������� ��������� ������
	handle = Provider->Handle->AcquireContainer(nativeName, mode); 

	// ��������� ����� ��������
	this->mode = mode & ~CRYPT_NEWKEYSET; 

	// �������� ��� ��������������
	CredentialsManager^ credentialsManager = 
		ExecutionContext::GetProviderCache(Provider->Name); 
		
	// �������� ������ �� ����
	Auth::PasswordCredentials^ credentials = 
		(Auth::PasswordCredentials^)credentialsManager->GetData(
			Info, "USER", Auth::PasswordCredentials::typeid
	); 
	// �������� ������ �� ����
	if (credentials == nullptr) credentials = 
		(Auth::PasswordCredentials^)credentialsManager->GetData(
			Store->Info, "USER", Auth::PasswordCredentials::typeid
	); 
	// ��� ������� ������ � ����	
	if (credentials != nullptr) { String^ password = credentials->Password; 

		// ������� ������������ ������
		try { handle->SetString(PP_KEYEXCHANGE_PIN, password, 0); } catch (Exception^) {}
	}
}

void Aladdin::CAPI::CSP::Container::DetachHandle()
{$
	// ������� ���������
	CSP::Handle::Release(handle); handle = nullptr; 
}

void Aladdin::CAPI::CSP::Container::SetCertificateContext(PCCERT_CONTEXT pCertificateContext)
{$
	// ������� ����� ���������� �������
	array<BYTE>^ content = gcnew array<BYTE>(pCertificateContext->cbCertEncoded); 

	// ����������� ���������� �����������
	Marshal::Copy(IntPtr(pCertificateContext->pbCertEncoded), content, 0, content->Length); 

	// ����� ������������� �����
	array<BYTE>^ keyID = GetKeyPair(gcnew CAPI::Certificate(content)); 

	// �������� ������ ����
	Using<CSP::PrivateKey^> privateKey((CSP::PrivateKey^)GetPrivateKey(keyID)); 
	
	// ���������� ��� ����������
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(Provider->Name); 

	// ���������� ��� ����������
	pin_ptr<CONST WCHAR> szContainer = PtrToStringChars(
		Store->GetNativeContainerName(Name->ToString())
	); 
	// ������� ���������� � ����������
	CRYPT_KEY_PROV_INFO info = { const_cast<PWSTR>(szProvider), 
		const_cast<PWSTR>(szContainer), Provider->Type, 
		mode & CRYPT_MACHINE_KEYSET, 0, 0, privateKey.Get()->KeyType
	};
	// ������� ���������� � ���������� � ����������
	AE_CHECK_WINAPI(::CertSetCertificateContextProperty(
		pCertificateContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &info
	)); 
}

///////////////////////////////////////////////////////////////////////
// �������������� ��������
///////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::Container::IsAuthenticationRequired(Exception^ e)
{$
	// ��������� ����� ��������
	if ((mode & CRYPT_SILENT) == 0) return false; 

	// ������� ������� ����������
	return Store->IsAuthenticationRequired(e); 
}

array<Aladdin::CAPI::Credentials^>^ Aladdin::CAPI::CSP::Container::Authenticate()
{$ 
	// ������� ������� �������
	array<Credentials^>^ results = CAPI::Container::Authenticate(); 

	// ��������� ������������� �������� ��������������
	if (!Store->HasAuthentication) return results; 

	// �������� ��� ��������������
	CredentialsManager^ credentialsManager = 
		ExecutionContext::GetProviderCache(Provider->Name); 

	// �������� ������ �� ����
	Auth::PasswordCredentials^ credentials = 
		(Auth::PasswordCredentials^)credentialsManager->GetData(
			Store->Info, "USER", Auth::PasswordCredentials::typeid
	); 
	// ��� ������� ������ � ����
	if (credentials != nullptr) { String^ password = credentials->Password; 
			
		// ������� ������������ ������
		Handle->SetString(PP_KEYEXCHANGE_PIN, password, 0); 
	}
	return results; 
}

///////////////////////////////////////////////////////////////////////
// ����� ��������
///////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CSP::Container::GetKeyType(String^ keyOID, KeyUsage keyUsage)
{$
	DWORD spec = AT_KEYEXCHANGE;  

	KeyUsage signMask = KeyUsage::DigitalSignature | KeyUsage::CertificateSignature | 
		                KeyUsage::CrlSignature     | KeyUsage::NonRepudiation; 
	KeyUsage keyxMask = KeyUsage::KeyEncipherment  | KeyUsage::KeyAgreement; 

	// ������� �������������� ����
	keyUsage = keyUsage & (signMask | keyxMask); 

	// � ����������� �� ������� �������������
	if ((keyUsage & signMask) != KeyUsage::None) 
	{
		// ��������������� ������ �������������
		keyUsage = keyUsage | signMask; spec = AT_SIGNATURE; 
	}
	// � ����������� �� ������� �������������
	if ((keyUsage & keyxMask) != KeyUsage::None) 
	{
		// ��������������� ������ �������������
		keyUsage = keyUsage | keyxMask; spec = AT_KEYEXCHANGE; 
	}
	// ��� ���� ��������� ������
	for (DWORD keyType = AT_KEYEXCHANGE; keyType <= AT_SIGNATURE; keyType++)
	{
		// ������� �������������
		array<BYTE>^ keyID = gcnew array<BYTE>(1) { (BYTE)keyType }; 

		// ������� ������������� ����� �� ���������
		KeyUsage decodedUsage = KeyUsage::None; 

		// ������� ������������� ����� �� ���������
		if (keyType == AT_KEYEXCHANGE) decodedUsage = decodedUsage | keyxMask; 
		if (keyType == AT_SIGNATURE  ) decodedUsage = decodedUsage | signMask; 

		// �������� ����������
		Certificate^ certificate = GetCertificate(keyID);
			
		// ������� ������������� ����� �� ���������
		if (certificate != nullptr) decodedUsage = decodedUsage | certificate->KeyUsage; 
				
		// ������� �������������� ����
		decodedUsage = decodedUsage & (signMask | keyxMask); 

		// ��������� ���������� ������� �������������
		if ((decodedUsage & keyUsage) == decodedUsage) return keyType; 
	}
	// ����������� ��� ������������ �����
	array<array<BYTE>^>^ keyIDs = GetKeyIDs(); 
	
	// ��������� ������� ������
	if (keyIDs->Length == 0) return spec; if (keyIDs->Length == 2) return 0;

	// ������� �������� ����
	spec = (keyIDs[0][0] == AT_KEYEXCHANGE) ? AT_SIGNATURE : AT_KEYEXCHANGE; 

	// ��� ������������ ������
	if ((keyUsage & keyxMask) != KeyUsage::None)
	{
		// ��������� ������� ���������� �����
		if (spec == AT_KEYEXCHANGE) return spec; 
	}
	// ��� ������������ �������
	if ((keyUsage & signMask) != KeyUsage::None)
	{
		// ��������� ������� ���������� �����
		if (spec == AT_SIGNATURE) return spec; 
	}
	// ��������� ���������� �������� �������������
	return (keyUsage == KeyUsage::None) ? spec : 0; 
}

array<array<BYTE>^>^ Aladdin::CAPI::CSP::Container::GetKeyIDs()
{$
	// ������� ������ ���������������
	List<array<BYTE>^>^ keyIDs = gcnew List<array<BYTE>^>(); 

	// ��� ���� ��������� ������
	for (DWORD keyType = AT_KEYEXCHANGE; keyType <= AT_SIGNATURE; keyType++)
	{
		// ������� �������������
		array<BYTE>^ keyID = gcnew array<BYTE>(1) { (BYTE)keyType }; 

		// �������� ��������� ��������� �����
		KeyHandle^ hKeyPair = Handle->GetUserKey(keyType); 
		
		// ��������� ������� �����
		if (hKeyPair != nullptr) { CSP::Handle::Release(hKeyPair); keyIDs->Add(keyID); }
	}
	return keyIDs->ToArray(); 
}

Aladdin::CAPI::IPublicKey^ 
Aladdin::CAPI::CSP::Container::GetPublicKey(array<BYTE>^ keyID)
{$
	// �������� ��������� ��������� �����
	DWORD keyType; Using<KeyHandle^> hPublicKey(GetUserKey(keyID, OUT keyType)); 

	// ��������� ������� ��������� �����
	if (hPublicKey.Get() == nullptr) return nullptr; 

	// �������� �������� ����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hPublicKey.Get()); 

	// ������������� �������� ����
	return Provider->DecodePublicKey(publicKeyInfo); 
}

Aladdin::CAPI::IPrivateKey^ Aladdin::CAPI::CSP::Container::GetPrivateKey(array<BYTE>^ keyID)
{$
	// �������� ��������� ������� �����
	DWORD keyType; Using<KeyHandle^> hKeyPair(GetUserKey(keyID, OUT keyType)); 

	// ��������� ������� �����
	if (hKeyPair.Get() == nullptr) throw gcnew Win32Exception(NTE_NO_KEY);

	// �������� �������� ����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// ������������� �������� ����
	IPublicKey^ publicKey = Provider->DecodePublicKey(publicKeyInfo); 

	// ������� ������ ���� 
	return Provider->GetPrivateKey(this, publicKey, hKeyPair.Get(), keyType); 
}

///////////////////////////////////////////////////////////////////////
// ���������� �������������
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CSP::Container::GetCertificate(array<BYTE>^ keyID) 
{$
	// �������� ��������� ���� ������
	DWORD keyType; Using<KeyHandle^> hKeyPair(GetUserKey(keyID, OUT keyType)); 

	// ��������� ������� ��������� �����
	if (hKeyPair.Get() == nullptr) return nullptr; 

	// �������� p�������������� �������� ����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// �������� ���������� ��������� �����
	return Store->GetCertificate(hKeyPair.Get(), publicKeyInfo); 
}

void Aladdin::CAPI::CSP::Container::SetCertificateChain(
	array<BYTE>^ keyID, array<Certificate^>^ certificateChain)
{$
	// �������� ��������� ���� ������
	DWORD keyType; Using<KeyHandle^> hKeyPair(GetUserKey(keyID, OUT keyType)); 

	// ��������� ������� ��������� �����
	if (hKeyPair.Get() == nullptr) throw gcnew Win32Exception(NTE_NO_KEY); 

	// ���������� ���������� ��������� �����
	return Store->SetCertificateChain(hKeyPair.Get(), certificateChain); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Container::SetKeyPair(
	IRand^ rand, KeyPair^ keyPair, KeyUsage keyUsage, KeyFlags keyFlags)
{$
	// ��������� ������� ����������
	if (keyPair == nullptr) throw gcnew ArgumentException(); 

	// ��� �������� ��������������
	DWORD keyType = 0; array<BYTE>^ keyID = keyPair->KeyID; if (keyID != nullptr)
	{
		// ��������� ������������ ��������������
		if (keyID->Length != 1) throw gcnew Win32Exception(NTE_BAD_UID); keyType = keyID[0];
	}
	// ���������� ��� ����� 
	if (keyType == 0) keyType = GetKeyType(keyPair->PublicKey->KeyOID, keyUsage); 

	// ��� ������ ��������� ����������
	if (keyType == 0) throw gcnew Win32Exception(NTE_NO_MORE_ITEMS);
	
    // ������� ������� ����������������
    DWORD flags = ((keyFlags & KeyFlags::Exportable) != KeyFlags::None) ? CRYPT_EXPORTABLE : 0; 

	// ������������� ���� � ���������
	Using<KeyHandle^> hKeyPair(Provider->ImportKeyPair(
		this, keyType, flags, keyPair->PublicKey, keyPair->PrivateKey
	));
	// ������� ����
	Using<PrivateKey^> cspPrivateKey(Provider->GetPrivateKey(
		this, keyPair->PublicKey, hKeyPair.Get(), keyType
	)); 
	// ������� ������������� �����
	return cspPrivateKey.Get()->KeyID; 
}

void Aladdin::CAPI::CSP::Container::DeleteKeys() 
{$
	// ������� ���������
	DetachHandle(); Store->DeleteObject(Name, Authentications); 

	// ������� ��������� ������
	AttachHandle(Mode | CRYPT_NEWKEYSET); 
}

///////////////////////////////////////////////////////////////////////////
// �������� � ������ ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Container::GenerateKeyPair(
	IntPtr hwnd, ALG_ID algID, DWORD flags)
{$
	// ��� ���������� ��������� ����
	if ((Mode & CRYPT_SILENT) != 0 || hwnd == IntPtr::Zero)
	{
		// ������������� ���� � ����������
		return Handle->GenerateKey(algID, flags); 
	}
	else {
		// ������� ��������� ����
		HWND windowHandle = (hwnd != IntPtr::Zero) ? (HWND)hwnd.ToPointer() : ::GetActiveWindow(); 

		// ���������� �������� ����
		Handle->SetParam(PP_CLIENT_HWND, IntPtr(&windowHandle), 0); 
		try {
			// ������������� ���� � ����������
			windowHandle = NULL; return Handle->GenerateKey(algID, flags);
		}
		// �������� �������� ����
		finally { Handle->SetParam(PP_CLIENT_HWND, IntPtr(&windowHandle), 0); }
	}
} 

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Container::ImportKey(
	KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags)
{$
	// ������������� ���� � ���������
	return Handle->ImportKey(hImportKey, ptrBlob, cbBlob, flags); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Container::ExportKey(
    KeyHandle^ hKey, KeyHandle^ hExportKey, DWORD exportType, DWORD flags)
{$
	// ���������� ������ ������
	DWORD cbBlob = hKey->Export(hExportKey, exportType, flags, IntPtr::Zero, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

	// �������������� ����
	cbBlob = hKey->Export(hExportKey, exportType, flags, IntPtr(ptrBuffer), cbBlob);

	// �������� ������ ������
	Array::Resize(buffer, cbBlob); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CSP::Container::Decrypt(
	KeyHandle^ hKey, array<BYTE>^ data, DWORD flags)
{$
	// ������������ ������
	return hKey->Decrypt(data, flags); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Container::SignHash(
	DWORD keyType, HashHandle^ hHash, DWORD flags) 
{$
	// ��������� ���-��������
	return Handle->SignHash(keyType, hHash, flags); 
}

