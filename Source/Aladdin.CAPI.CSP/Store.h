#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// Сервис парольной аутентификации
	///////////////////////////////////////////////////////////////////////////
	public ref class PasswordService : Auth::PasswordService
	{
		// конструктор
		public: PasswordService(SecurityObject^ obj, CSP::Handle^ handle) 
			
			// сохранить переданные параметры
			: Auth::PasswordService(obj, "USER") 
        
			// сохранить переданные параметры
			{ this->handle = handle; } private: Handle^ handle;

		// описатель контейнера
		protected: property CSP::Handle^ Handle { CSP::Handle^ get() { return handle; }}

		// установить аутентификационные данные
		protected: virtual void SetPassword(String^ password) override
		{
			// установить пароль на контейнер
			handle->SetString(PP_KEYEXCHANGE_PIN, password, 0); 
		}
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Тип устройства хранения 
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderStore : ContainerStore
	{
		// тип класса контейнера и режим открытия
		private: String^ name; private: Type^ containerType; private: DWORD mode;

		// конструктор
		protected: ProviderStore(CSP::Provider^ provider, 
			CAPI::Scope scope, String^ name, Type^ containerType, DWORD mode) 
			
			// сохранить переданные параметры
			: ContainerStore(provider, scope) 
		{ 
			// сохранить переданные параметры
			this->name = name; this->containerType = containerType; this->mode = mode; 
		} 
		// конструктор
		protected: ProviderStore(SecurityStore^ store, 
			String^ name, Type^ containerType, DWORD mode) : ContainerStore(store) 
		{ 
			// сохранить переданные параметры
			this->name = name; this->containerType = containerType; this->mode = mode; 
		} 
        // криптографический провайдер
        public: property CSP::Provider^ Provider 
		{ 
			// криптографический провайдер
			CSP::Provider^ get() new { return (CSP::Provider^)ContainerStore::Provider; } 
		} 
		// имя хранилища
		public: virtual property Object^ Name { Object^ get() override sealed { return name; }}

		// способ размещения контейнера
		protected: property DWORD Mode { DWORD get() { return mode; }}

		// признак наличия аутентификации
		public: virtual property bool HasAuthentication { bool get() { return false; }}
		// проверить наличие исключения аутентификации
		public: virtual bool IsAuthenticationRequired(Exception^ e) override; 

		// определить имя контейнера для провайдера
		public: virtual String^ GetNativeContainerName(String^ name) { return name; }
		// перечисление контейнеров
		public: virtual array<String^>^ EnumerateObjects() override; 

		// создать контейнер
		public: virtual SecurityObject^ CreateObject(IRand^ rand, 
			Object^ name, Object^ authenticationData, ...array<Object^>^ parameters) override;
		// открыть контейнер 
		public: virtual SecurityObject^ OpenObject(
			Object^ name, FileAccess access) override; 
		// удалить контейнер
		public: virtual void DeleteObject(
			Object^ name, array<CAPI::Authentication^>^ authentications) override; 

		// получить сертификат открытого ключа
		public protected: virtual Certificate^ GetCertificate(
			KeyHandle^ hKeyPair, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo
		);
		// получить цепь сертификатов
		public protected: virtual array<Certificate^>^ GetCertificateChain(Certificate^ certificate); 

		// сохранить сертификат открытого ключа
		public protected: virtual void SetCertificateChain(
			KeyHandle^ hKeyPair, array<Certificate^>^ certificateChain
		); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Хранилище контейнеров в реестре
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : ProviderStore
	{
        // описатель хранилища
		private: StoreHandle^ handle; 

		// конструктор
		public: RegistryStore(CSP::Provider^ provider, CAPI::Scope scope, Type^ containerType, DWORD mode);  
		// деструктор
		public: virtual ~RegistryStore();   

		// описатель хранилища
		protected: property StoreHandle^ Handle { StoreHandle^ get() { return handle; }}
		// перечисление контейнеров
		public: virtual array<String^>^ EnumerateObjects() override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Смарт-карта как устройства хранения
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : ProviderStore
	{
        // описатель смарт-карты
		private: Using<StoreHandle^> handle; 

		// конструктор
		public: static SCardStore^ Create(SecurityStore^ store, String^ name, DWORD mode) 
		{
			// создать объект смарт-карты
			SCardStore^ cardStore = gcnew SCardStore(store, CSP::Container::typeid, name, mode); 

			// вернуть прокси
			try { return (SCardStore^)Proxy::SecurityObjectProxy::Create(cardStore); } 

			// обработать возможную ошибку
			catch (Exception^) { delete cardStore; throw; }
		}
		// конструктор
		protected: SCardStore(SecurityStore^ store, Type^ containerType, String^ name, DWORD mode); 
		// деструктор
		public: virtual ~SCardStore();  

		// описатель смарт-карты
		protected: property StoreHandle^ Handle { StoreHandle^ get() { return handle.Get(); }}

		// признак наличия аутентификации
		public: virtual property bool HasAuthentication { bool get() override { return true; }}

		// поддерживаемые типы аутентификации
		public: virtual array<Type^>^ GetAuthenticationTypes(String^ user) override
        { 
            // поддерживается парольная аутентификация
			return gcnew array<Type^> { Auth::PasswordCredentials::typeid }; 
        } 
		// получить сервис аутентификации
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override
		{
			// проверить тип аутентификации
			if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
			{
				// вернуть протокол аутентификации
				return gcnew PasswordService(this, Handle); 
			}
			return nullptr; 
		}
		// уникальное имя хранилища
		public: virtual String^ GetUniqueID() override; 

		// определить имя контейнера для провайдера
		public: virtual String^ GetNativeContainerName(String^ name) override
		{ 
			// определить имя контейнера для провайдера
			return String::Format("\\\\.\\{0}\\{1}", Name, name); 
		}
		// перечисление контейнеров
		public: virtual array<String^>^ EnumerateObjects() override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// Смарт-карты как устройство хранения
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStores : SecurityStore
	{
		// конструктор
		public: SCardStores(CSP::Provider^ provider, CAPI::Scope scope, DWORD mode)

			// сохранить переданные параметры
			: SecurityStore(provider, scope) { this->mode = mode; } private: DWORD mode;

        // криптографический провайдер
        public: property CSP::Provider^ Provider 
		{ 
			// криптографический провайдер
			CSP::Provider^ get() new { return (CSP::Provider^)SecurityStore::Provider; } 
		} 
		// имя хранилища
		public: virtual property Object^ Name { Object^ get() override { return "Card"; }}

		// способ размещения контейнера
		protected: property DWORD Mode { DWORD get() { return mode; }}

		// перечисление контейнеров
		public: virtual array<String^>^ EnumerateObjects() override; 
		// открыть контейнер 
		public: virtual SecurityObject^ OpenObject(Object^ name, FileAccess access) override
		{
			// вернуть смарт-карту
			return SCardStore::Create(this, name->ToString(), mode); 
		}
	};
}}}
