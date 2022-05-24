#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////////
	// Сервис парольной аутентификации
	///////////////////////////////////////////////////////////////////////////
	public ref class PasswordService : Auth::PasswordService
	{
		// конструктор
		public: PasswordService(SecurityObject^ obj, NKeyHandle^ handle) 
			
			// сохранить переданные параметры
			: Auth::PasswordService(obj, "USER") 
        
			// сохранить переданные параметры
			{ this->handle = handle; } private: NKeyHandle^ handle;

		// установить аутентификационные данные
		protected: virtual void SetPassword(String^ password) override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Устройства хранения 
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderStore : ContainerStore
	{
		// имя хранилища и режим открытия
		private: String^ name; private: DWORD mode; 

		// конструктор
		public: ProviderStore(NProvider^ provider, CAPI::Scope scope, String^ name, DWORD mode)

			// сохранить переданные параметры
			: ContainerStore(provider, scope) { this->name = name; this->mode = mode; } 

		// конструктор
		public: ProviderStore(SecurityStore^ store, String^ name, DWORD mode) 
			
			// сохранить переданные параметры
			: ContainerStore(store) { this->name = name; this->mode = mode; }

        // криптографический провайдер
        public: property NProvider^ Provider 
		{ 
			// криптографический провайдер
			NProvider^ get() new { return (NProvider^)ContainerStore::Provider; } 
		} 
		// имя хранилища
		public: virtual property Object^ Name { Object^ get() override { return name; }}

		// способ размещения контейнера
		protected: property DWORD Mode { DWORD get() { return mode; }}

		// признак наличия аутентификации
		public: virtual property bool HasAuthentication { bool get() { return false; }}
		// проверить необходимость аутентификации
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
		public: virtual void DeleteObject(Object^ name, 
			array<CAPI::Authentication^>^ authentications) override; 

		// получить сертификат открытого ключа
		public protected: virtual Certificate^ GetCertificate(NKeyHandle^ hPrivateKey, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo
		);
		// получить цепь сертификатов
		public protected: virtual array<Certificate^>^ GetCertificateChain(Certificate^ certificate); 

		// сохранить сертификат открытого ключа
		public protected: virtual void SetCertificateChain(
			NKeyHandle^ hPrivateKey, array<Certificate^>^ certificateChain
		); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Хранилище контейнеров в реестре
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CAPI::CNG::ProviderStore
	{
		// конструктор
		public: RegistryStore(NProvider^ provider, CAPI::Scope scope, DWORD mode); 
			
		// перечислить контейнеры
		public: virtual array<String^>^ EnumerateObjects() override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Смарт-карта как устройства хранения
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : ProviderStore
	{
		// описатель смарт-карты
		private: NKeyHandle^ hCard; 

		// конструктор
		public: static SCardStore^ Create(SecurityStore^ store, String^ name, DWORD mode) 
		{
			// создать объект смарт-карты
			SCardStore^ cardStore = gcnew SCardStore(store, name, mode); 

			// вернуть прокси
			try { return (SCardStore^)Proxy::SecurityObjectProxy::Create(cardStore); }

			// обработать возможную ошибку
			catch (Exception^) { delete cardStore; throw; }
		}
		// конструктор
		protected: SCardStore(SecurityStore^ store, String^ name, DWORD mode);   
		// деструктор
		public: virtual ~SCardStore() { Handle::Release(hCard); }

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
				return gcnew PasswordService(this, hCard); 
			}
			return nullptr; 
		}
		// указать пароль
		public: property String^ Password { void set(String^ value)
		{ 
            // указать парольную аутентификацию
            CAPI::Authentication^ authentication = 
				gcnew Auth::PasswordCredentials("USER", value); 

            // установить и выполнить аутентификацию
            Authentication = authentication; Authenticate(); 
		}}
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
		public: SCardStores(NProvider^ provider, CAPI::Scope scope, DWORD mode)

			// сохранить переданные параметры
			: SecurityStore(provider, scope) { this->mode = mode; } private: DWORD mode;

        // криптографический провайдер
        public: property NProvider^ Provider 
		{ 
			// криптографический провайдер
			NProvider^ get() new { return (NProvider^)SecurityStore::Provider; } 
		} 
		// имя хранилища
		public: virtual property Object^ Name { Object^ get() override { return "Card"; }}

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
