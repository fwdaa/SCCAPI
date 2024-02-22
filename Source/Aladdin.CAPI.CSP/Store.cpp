#include "stdafx.h"
#include "Store.h"
#include "Container.h"
#include "CertificateStore.h"

#ifndef CRYPT_DEFAULT_CONTAINER_OPTIONAL
#define CRYPT_DEFAULT_CONTAINER_OPTIONAL 0x80
#endif

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Store.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ���������� �������� 
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::ProviderStore::IsAuthenticationRequired(Exception^ e)
{$
	// ��������� ��� ����������
	if (dynamic_cast<Win32Exception^>(e) == nullptr) return false; 

	// ���������� ��� ������
	DWORD code = (((Win32Exception^)e)->NativeErrorCode); 

	// ��������� ��� ������
	if (code == NTE_SILENT_CONTEXT || code == NTE_FAIL) return TRUE; 

	// ��������� ��� ������
	return code == SCARD_W_SECURITY_VIOLATION || 
		   code == SCARD_E_INVALID_CHV || code == SCARD_W_WRONG_CHV; 
}

array<String^>^ Aladdin::CAPI::CSP::ProviderStore::EnumerateObjects()
{$
	// ����������� ����������
	if (Scope == CAPI::Scope::User) return Provider->Handle->EnumerateContainers(0); 
	else {
		// ������� ����� �������� 
		DWORD openMode = Mode | CRYPT_MACHINE_KEYSET | CRYPT_VERIFYCONTEXT | CRYPT_SILENT; 

		// ������� ��������� ���������
		Using<StoreHandle^> handle(Provider->Handle->AcquireStore(nullptr, openMode));
		
		// ����������� ���������� �����������
		return handle.Get()->EnumerateContainers(0); 
	}
}

Aladdin::CAPI::SecurityObject^ Aladdin::CAPI::CSP::ProviderStore::CreateObject(
	IRand^ rand, Object^ name, Object^ authenticationData, ...array<Object^>^ parameters)
{$
	// ������� ������ ������ ������
	BindingFlags flags = BindingFlags::Static | BindingFlags::InvokeMethod | BindingFlags::Public; 

	// ����� �������� ������
	MethodInfo^ method = containerType->GetMethod("Create", flags); 

	// ��������� ������� ������
	if (method == nullptr) throw gcnew InvalidOperationException(); 

	// ������� ��������� ������
	array<Object^>^ args = gcnew array<Object^> { 
		this, name->ToString(), mode | CRYPT_NEWKEYSET | CRYPT_SILENT
	}; 
	try { 
		// ������� ���������
		Container^ container = (Container^)method->Invoke(nullptr, args); 

		// ��� �������� ������
		if (authenticationData != nullptr)
		{
			// ��������� �������������� ����
			String^ password = (String^)authenticationData; 

			// ��������� �������������� ��������������
			container->Authentication = gcnew Auth::PasswordCredentials("USER", password); 
		}
		return container; 
	}
	// ���������� ��������� ����������
	catch (TargetInvocationException^ e) { throw e->InnerException; }
}

Aladdin::CAPI::SecurityObject^ Aladdin::CAPI::CSP::ProviderStore::OpenObject(
	Object^ name, FileAccess access)
{$
	// ������� ������ ������ ������
	BindingFlags flags = BindingFlags::Static | BindingFlags::InvokeMethod | BindingFlags::Public; 

	// ����� �������� ������
	MethodInfo^ method = containerType->GetMethod("Create", flags); 

	// ��������� ������� ������
	if (method == nullptr) throw gcnew InvalidOperationException(); 

	// ������� ��������� ������
	array<Object^>^ args = gcnew array<Object^> { this, name->ToString(), mode | CRYPT_SILENT }; 
	try {
		// ������� ���������
		try { return (Container^)method->Invoke(nullptr, args); }  

		// ���������� ��������� ����������
		catch (TargetInvocationException^ e) { throw e->InnerException; }
	}
	// ��� ������������� ������
	catch (Win32Exception^ e)
	{
		// ��������� ��� ������
		if (e->NativeErrorCode == NTE_BAD_KEYSET    ) throw gcnew NotFoundException();
		if (e->NativeErrorCode == NTE_KEYSET_NOT_DEF) throw gcnew NotFoundException();
		throw; 
	}
}

void Aladdin::CAPI::CSP::ProviderStore::DeleteObject(
	Object^ name, array<CAPI::Authentication^>^ authentications)
{$
	// ������� ������ ��� ����������
	String^ nativeName = GetNativeContainerName(name->ToString()); 

	// ������� ���������
	try { Provider->Handle->DeleteContainer(nativeName, mode | CRYPT_SILENT); }

	// ��� ������������� ������
	catch (Win32Exception^ e)
	{
		// ��������� ��� ������
		if (e->NativeErrorCode == NTE_BAD_KEYSET    ) return;
		if (e->NativeErrorCode == NTE_KEYSET_NOT_DEF) return;
		throw; 
	}
	// ������� ������� �������
	ContainerStore::DeleteObject(name, authentications); 
}

Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CSP::ProviderStore::GetCertificate(KeyHandle^ hKeyPair, 
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	try {
		// �������� ���������� ��������� �����
		array<BYTE>^ encoded = hKeyPair->GetSafeParam(KP_CERTIFICATE, 0); 

		// �������� ���������� ��������� �����
		return (encoded != nullptr) ? gcnew Certificate(encoded) : nullptr; 
	}
	// ���������� ���������� �������
	catch (Exception^) { return nullptr; } 
}

array<Aladdin::CAPI::Certificate^>^ 
Aladdin::CAPI::CSP::ProviderStore::GetCertificateChain(Certificate^ certificate)
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// �������� ������� ������������
	return CertificateStore::GetCertificateChain("System", location, certificate); 
}

void Aladdin::CAPI::CSP::ProviderStore::SetCertificateChain(
	KeyHandle^ hKeyPair, array<Certificate^>^ certificateChain)
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// ���������� ����������
	hKeyPair->SetParam(KP_CERTIFICATE, certificateChain[0]->Encoded, 0); 

	// ��������� ������� ������������
	CertificateStore::SetCertificateChain("System", location, certificateChain, 1); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ����������� � �������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::RegistryStore::RegistryStore(CSP::Provider^ provider, 
	
	// ��������� ���������� ���������
	CAPI::Scope scope, Type^ containerType, DWORD mode) : ProviderStore(provider, scope, 
		
	// ������� ��� ���������
	(scope == CAPI::Scope::System) ? "HKLM" : "HKCU", containerType, 

	// ������� ����� ��������
	(scope == CAPI::Scope::System) ? (mode | CRYPT_MACHINE_KEYSET) : mode) 
{
	// ������� ����� �������� 
	DWORD openMode = Mode | CRYPT_VERIFYCONTEXT | CRYPT_SILENT; 

	// ������� ��������� ���������
	handle = Provider->Handle->AcquireStore(nullptr, openMode);
}

Aladdin::CAPI::CSP::RegistryStore::~RegistryStore()  
{$ 
	// ���������� ������� ���������
	CSP::Handle::Release(handle); 
} 

array<String^>^ Aladdin::CAPI::CSP::RegistryStore::EnumerateObjects()
{$
	// ����������� ���������� �����������
	return handle->EnumerateContainers(0); 
}

///////////////////////////////////////////////////////////////////////////
// �����-����� ��� ���������� ��������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SCardStore::SCardStore(
	SecurityStore^ store, Type^ containerType, String^ name, DWORD mode) 

	// ��������� ���������� ���������
	: ProviderStore(store, name, containerType, mode)
{
	// ���������� ��� �����������
	String^ nativeName = String::Format("\\\\.\\{0}\\", Name->ToString()); 
	try { 
		// ������� ����� ��������
		DWORD openMode = Mode | CRYPT_DEFAULT_CONTAINER_OPTIONAL | CRYPT_SILENT; 

		// ������� ��������� ���������
		handle.Attach(Provider->Handle->AcquireStore(nativeName, openMode)); 
	}
	// ��� ������������� ������
	catch (Win32Exception^ e)
	{
		// ��������� ��� ������
		if (e->NativeErrorCode != NTE_BAD_FLAGS) throw;

		// ������� ����� ��������
		DWORD openMode = Mode | CRYPT_SILENT; 

		// ������� ��������� ���������
		handle.Attach(Provider->Handle->AcquireStore(nativeName, openMode)); 
	}
}

Aladdin::CAPI::CSP::SCardStore::~SCardStore() { $ } 

String^ Aladdin::CAPI::CSP::SCardStore::GetUniqueID()
{$
    // �������� ���������� �����-����
    PCSC::Windows::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// ������� ������� ���������
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// �������� ���������� ������������� �����-�����
	return provider->GetCardUniqueID(readerScope, Name->ToString()); 
}

array<String^>^ Aladdin::CAPI::CSP::SCardStore::EnumerateObjects()
{$
	try {
		// ����������� ���������� �����������
		return handle.Get()->EnumerateContainers(0); 
	}
	// ���������� ��������� ������
	catch(Exception^) {} return gcnew array<String^>(0); 
}

///////////////////////////////////////////////////////////////////////////
// �����-����� ��� ���������� ��������
///////////////////////////////////////////////////////////////////////////
array<String^>^ Aladdin::CAPI::CSP::SCardStores::EnumerateObjects()
{$
	// ������� ������ ���� ������������
	List<String^>^ names = gcnew List<String^>(); 

    // �������� ���������� �����-����
    PCSC::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// ������� ������� ���������
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// ����������� �����������
	array<PCSC::Reader^>^ readers = provider->EnumerateReaders(readerScope); 

	// ��� ������ �����-�����
	for (int i = 0; i < readers->Length; i++) 
	try {
		// ��������� ������� �����-����� ������� ��� �����������. 
		// !!! ��������� ����������� ����� �� ������������ 
		// �����-����� � ����������� !!!
		// if (readers[i]->GetState() != PCSC::ReaderState::Card) continue; 

		// ������� ���������
		// Using<SecurityObject^> store(OpenObject(readers[i]->Name, FileAccess::Read)); 

		// �������� ��� � ������
		names->Add(readers[i]->Name);
	}
	// ������� ������ ����
	catch (Exception^) {} return names->ToArray(); 
}
