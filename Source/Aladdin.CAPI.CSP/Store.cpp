#include "stdafx.h"
#include "Store.h"
#include "Container.h"
#include "CertificateStore.h"

#ifndef CRYPT_DEFAULT_CONTAINER_OPTIONAL
#define CRYPT_DEFAULT_CONTAINER_OPTIONAL 0x80
#endif

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Store.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Устройства хранения 
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::ProviderStore::IsAuthenticationRequired(Exception^ e)
{$
	// проверить тип исключения
	if (dynamic_cast<Win32Exception^>(e) == nullptr) return false; 

	// определить код ошибки
	DWORD code = (((Win32Exception^)e)->NativeErrorCode); 

	// проверить код ошибки
	if (code == NTE_SILENT_CONTEXT || code == NTE_FAIL) return TRUE; 

	// проверить код ошибки
	return code == SCARD_W_SECURITY_VIOLATION || 
		   code == SCARD_E_INVALID_CHV || code == SCARD_W_WRONG_CHV; 
}

array<String^>^ Aladdin::CAPI::CSP::ProviderStore::EnumerateObjects()
{$
	// перечислить контейнеры
	if (Scope == CAPI::Scope::User) return Provider->Handle->EnumerateContainers(0); 
	else {
		// указать режим открытия 
		DWORD openMode = Mode | CRYPT_MACHINE_KEYSET | CRYPT_VERIFYCONTEXT | CRYPT_SILENT; 

		// открыть описатель хранилища
		Using<StoreHandle^> handle(Provider->Handle->AcquireStore(nullptr, openMode));
		
		// перечислить контейнеры считывателя
		return handle.Get()->EnumerateContainers(0); 
	}
}

Aladdin::CAPI::SecurityObject^ Aladdin::CAPI::CSP::ProviderStore::CreateObject(
	IRand^ rand, Object^ name, Object^ authenticationData, ...array<Object^>^ parameters)
{$
	// указать способ поиска метода
	BindingFlags flags = BindingFlags::Static | BindingFlags::InvokeMethod | BindingFlags::Public; 

	// найти описание метода
	MethodInfo^ method = containerType->GetMethod("Create", flags); 

	// проверить наличие метода
	if (method == nullptr) throw gcnew InvalidOperationException(); 

	// указать аргументы метода
	array<Object^>^ args = gcnew array<Object^> { 
		this, name->ToString(), mode | CRYPT_NEWKEYSET | CRYPT_SILENT
	}; 
	try { 
		// создать контейнер
		Container^ container = (Container^)method->Invoke(nullptr, args); 

		// при указании пароля
		if (authenticationData != nullptr)
		{
			// выполнить преобразование типа
			String^ password = (String^)authenticationData; 

			// сохранить использованную аутентификацию
			container->Authentication = gcnew Auth::PasswordCredentials("USER", password); 
		}
		return container; 
	}
	// обработать возможное исключение
	catch (TargetInvocationException^ e) { throw e->InnerException; }
}

Aladdin::CAPI::SecurityObject^ Aladdin::CAPI::CSP::ProviderStore::OpenObject(
	Object^ name, FileAccess access)
{$
	// указать способ поиска метода
	BindingFlags flags = BindingFlags::Static | BindingFlags::InvokeMethod | BindingFlags::Public; 

	// найти описание метода
	MethodInfo^ method = containerType->GetMethod("Create", flags); 

	// проверить наличие метода
	if (method == nullptr) throw gcnew InvalidOperationException(); 

	// указать аргументы метода
	array<Object^>^ args = gcnew array<Object^> { this, name->ToString(), mode | CRYPT_SILENT }; 
	try {
		// открыть контейнер
		try { return (Container^)method->Invoke(nullptr, args); }  

		// обработать возможное исключение
		catch (TargetInvocationException^ e) { throw e->InnerException; }
	}
	// при возникновении ошибки
	catch (Win32Exception^ e)
	{
		// проверить код ошибки
		if (e->NativeErrorCode == NTE_BAD_KEYSET    ) throw gcnew NotFoundException();
		if (e->NativeErrorCode == NTE_KEYSET_NOT_DEF) throw gcnew NotFoundException();
		throw; 
	}
}

void Aladdin::CAPI::CSP::ProviderStore::DeleteObject(
	Object^ name, array<CAPI::Authentication^>^ authentications)
{$
	// указать полное имя контейнера
	String^ nativeName = GetNativeContainerName(name->ToString()); 

	// удалить контейнер
	try { Provider->Handle->DeleteContainer(nativeName, mode | CRYPT_SILENT); }

	// при возникновении ошибки
	catch (Win32Exception^ e)
	{
		// проверить код ошибки
		if (e->NativeErrorCode == NTE_BAD_KEYSET    ) return;
		if (e->NativeErrorCode == NTE_KEYSET_NOT_DEF) return;
		throw; 
	}
	// вызвать базовую функцию
	ContainerStore::DeleteObject(name, authentications); 
}

Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CSP::ProviderStore::GetCertificate(KeyHandle^ hKeyPair, 
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	try {
		// получить сертификат открытого ключа
		array<BYTE>^ encoded = hKeyPair->GetSafeParam(KP_CERTIFICATE, 0); 

		// получить сертификат открытого ключа
		return (encoded != nullptr) ? gcnew Certificate(encoded) : nullptr; 
	}
	// освободить выделенные ресурсы
	catch (Exception^) { return nullptr; } 
}

array<Aladdin::CAPI::Certificate^>^ 
Aladdin::CAPI::CSP::ProviderStore::GetCertificateChain(Certificate^ certificate)
{$
	// указать месторасположение хранилища в реестре
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// получить цепочку сертификатов
	return CertificateStore::GetCertificateChain("System", location, certificate); 
}

void Aladdin::CAPI::CSP::ProviderStore::SetCertificateChain(
	KeyHandle^ hKeyPair, array<Certificate^>^ certificateChain)
{$
	// указать месторасположение хранилища в реестре
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// установить сертификат
	hKeyPair->SetParam(KP_CERTIFICATE, certificateChain[0]->Encoded, 0); 

	// сохранить цепочку сертификатов
	CertificateStore::SetCertificateChain("System", location, certificateChain, 1); 
}

///////////////////////////////////////////////////////////////////////////
// Хранилище контейнеров в реестре
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::RegistryStore::RegistryStore(CSP::Provider^ provider, 
	
	// сохранить переданные параметры
	CAPI::Scope scope, Type^ containerType, DWORD mode) : ProviderStore(provider, scope, 
		
	// указать имя хранилища
	(scope == CAPI::Scope::System) ? "HKLM" : "HKCU", containerType, 

	// указать режим открытия
	(scope == CAPI::Scope::System) ? (mode | CRYPT_MACHINE_KEYSET) : mode) 
{
	// указать режим открытия 
	DWORD openMode = Mode | CRYPT_VERIFYCONTEXT | CRYPT_SILENT; 

	// открыть описатель хранилища
	handle = Provider->Handle->AcquireStore(nullptr, openMode);
}

Aladdin::CAPI::CSP::RegistryStore::~RegistryStore()  
{$ 
	// освободить ресурсы хранилища
	CSP::Handle::Release(handle); 
} 

array<String^>^ Aladdin::CAPI::CSP::RegistryStore::EnumerateObjects()
{$
	// перечислить контейнеры считывателя
	return handle->EnumerateContainers(0); 
}

///////////////////////////////////////////////////////////////////////////
// Смарт-карта как устройство хранения
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SCardStore::SCardStore(
	SecurityStore^ store, Type^ containerType, String^ name, DWORD mode) 

	// сохранить переданные параметры
	: ProviderStore(store, name, containerType, mode)
{
	// определить имя считывателя
	String^ nativeName = String::Format("\\\\.\\{0}\\", Name->ToString()); 
	try { 
		// указать режим открытия
		DWORD openMode = Mode | CRYPT_DEFAULT_CONTAINER_OPTIONAL | CRYPT_SILENT; 

		// открыть описатель хранилища
		handle.Attach(Provider->Handle->AcquireStore(nativeName, openMode)); 
	}
	// при возникновении ошибки
	catch (Win32Exception^ e)
	{
		// проверить код ошибки
		if (e->NativeErrorCode != NTE_BAD_FLAGS) throw;

		// указать режим открытия
		DWORD openMode = Mode | CRYPT_SILENT; 

		// открыть описатель хранилища
		handle.Attach(Provider->Handle->AcquireStore(nativeName, openMode)); 
	}
}

Aladdin::CAPI::CSP::SCardStore::~SCardStore() { $ } 

String^ Aladdin::CAPI::CSP::SCardStore::GetUniqueID()
{$
    // получить подсистему смарт-карт
    PCSC::Windows::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// указать область видимости
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// получить уникальный идентификатор смарт-карты
	return provider->GetCardUniqueID(readerScope, Name->ToString()); 
}

array<String^>^ Aladdin::CAPI::CSP::SCardStore::EnumerateObjects()
{$
	try {
		// перечислить контейнеры считывателя
		return handle.Get()->EnumerateContainers(0); 
	}
	// обработать возможную ошибку
	catch(Exception^) {} return gcnew array<String^>(0); 
}

///////////////////////////////////////////////////////////////////////////
// Смарт-карты как устройство хранения
///////////////////////////////////////////////////////////////////////////
array<String^>^ Aladdin::CAPI::CSP::SCardStores::EnumerateObjects()
{$
	// создать список имен считывателей
	List<String^>^ names = gcnew List<String^>(); 

    // получить подсистему смарт-карт
    PCSC::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// указать область видимости
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// перечислить считыватели
	array<PCSC::Reader^>^ readers = provider->EnumerateReaders(readerScope); 

	// для каждой смарт-карты
	for (int i = 0; i < readers->Length; i++) 
	try {
		// проверить наличие смарт-карты добаить имя считывателя. 
		// !!! Некоторые виртуальные среды не пробрасывают 
		// смарт-карту в считыватель !!!
		// if (readers[i]->GetState() != PCSC::ReaderState::Card) continue; 

		// открыть хранилище
		// Using<SecurityObject^> store(OpenObject(readers[i]->Name, FileAccess::Read)); 

		// добавить имя в список
		names->Add(readers[i]->Name);
	}
	// вернуть список имен
	catch (Exception^) {} return names->ToArray(); 
}
