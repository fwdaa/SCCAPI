#pragma once
#include "Handle.h"
#include "Store.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический контейнер. Поддерживаются три конфигурации 
	// аутентификации:
	// 1) отсутствие аутентификации (пример - контейнеры реестра Microsoft); 
	// 2) аутентификация собственно контейнера (пример - контейнеры реестра 
	//    CryptoPro); 
	// 3) аутентификация непосредственного хранилища контейнера 
	//    (пример - контейнеры на смарт-карте). В данном случае аутентификация 
	//    проводится через описатель хранилища (обычно открываемый с указанием 
	//    флага CRYPT_DEFAULT_CONTAINER_OPTIONAL), а затем аутентификация 
	//    пробрасывается на описатель контейнера. 
	///////////////////////////////////////////////////////////////////////////
	public ref class Container : CAPI::Container, IRandFactory
	{
        // описатель контейнера и режим открытия
		private: ContainerHandle^ handle; DWORD mode; 
	
        // конструктор
		public: static Container^ Create(ProviderStore^ store, String^ name, DWORD mode) 
		{
			// создать объект контейнера
			Container^ container = gcnew Container(store, name, mode); 

			// вернуть прокси
			try { return (Container^)Proxy::SecurityObjectProxy::Create(container); }

			// обработать возможную ошибку
			catch (Exception^) { delete container; throw; }
		}
		// конструктор
		protected: Container(ProviderStore^ store, String^ name, DWORD mode) : CAPI::Container(store, name)
		{
			// открыть описатель контейнера
			handle = nullptr; AttachHandle(mode);  
		}
		// деструктор
		public: virtual ~Container() { DetachHandle(); } 

        // криптографический провайдер
        public: property CSP::Provider^ Provider 
		{ 
			// криптографический провайдер
			CSP::Provider^ get() new { return Store->Provider; } 
		} 
        // хранилище контейнера
        public: property ProviderStore^ Store 
        {
            // хранилище контейнера
            ProviderStore^ get() new { return (ProviderStore^)CAPI::Container::Store; }
        }
        // информация контейнера
        public: virtual property SecurityInfo^ Info 
        {
            // хранилище контейнера
            SecurityInfo^ get() override sealed { return CAPI::Container::Info; }
        }
		// получить описатель контейнера
		public: property ContainerHandle^ Handle 
		{ 
			// получить описатель контейнера
			ContainerHandle^ get() { return handle; }
		}
		// режим открытия контейнера
        protected: property DWORD Mode { DWORD get() { return mode; }}

		// создать генератор случайных данных
		public: virtual IRand^ CreateRand(Object^ window); 

		///////////////////////////////////////////////////////////////////////
		// Операции с описателем контейнера
		///////////////////////////////////////////////////////////////////////
		protected: void AttachHandle(String^ nativeName, DWORD mode); 
		protected: void AttachHandle(DWORD mode)
		{
			// открыть описатель контейнера
			AttachHandle(Store->GetNativeContainerName(Name->ToString()), mode); 
		}
		protected: void DetachHandle(); 

		///////////////////////////////////////////////////////////////////////
		// Управление аутентификацией
		///////////////////////////////////////////////////////////////////////

		// проверить наличие исключения аутентификации
		public: virtual bool IsAuthenticationRequired(Exception^ e) override; 

		// поддерживаемые типы аутентификации
		public: virtual array<Type^>^ GetAuthenticationTypes(String^ user) override
        { 
			// проверить тип пользователя
			if (Store->HasAuthentication) return gcnew array<Type^>(0); 

            // поддерживается парольная аутентификация
			return gcnew array<Type^> { Auth::PasswordCredentials::typeid }; 
        } 
		// получить сервис аутентификации
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override
		{
			// проверить тип пользователя
			if (Store->HasAuthentication) return nullptr; 

			// проверить тип аутентификации
			if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
			{
				// вернуть протокол аутентификации
				return gcnew PasswordService(this, Handle); 
			}
			return nullptr; 
		}
		// выполнить аутентификацию
		public: virtual array<Credentials^>^ Authenticate() override; 

		///////////////////////////////////////////////////////////////////////
		// Поиск объектов
		///////////////////////////////////////////////////////////////////////

		// получить тип для нового ключа
		public protected: virtual DWORD GetKeyType(String^ keyOID, KeyUsage keyUsage); 

		// перечислить идентификаторы ключей
		public: virtual array<array<BYTE>^>^ GetKeyIDs() override; 

		// вернуть открытый ключ
		public: virtual IPublicKey^ GetPublicKey(array<BYTE>^ keyID) override; 

		// вернуть личный ключ
		public: virtual IPrivateKey^ GetPrivateKey(array<BYTE>^ keyID) override; 

		///////////////////////////////////////////////////////////////////////
		// Управление сертификатами и ключами
		///////////////////////////////////////////////////////////////////////

		// получить сертификат открытого ключа
		public: virtual Certificate^ GetCertificate(array<BYTE>^ keyID) override; 

		// сохранить сертификат открытого ключа
		public: virtual void SetCertificate(
			array<BYTE>^ keyID, Certificate^ certificate) override; 

		// связать сертификат с ключом
		public: void SetCertificateContext(PCCERT_CONTEXT pCertificateContext);

		// сохранить пару ключей
		public: virtual array<BYTE>^ SetKeyPair(IRand^ rand, 
			KeyPair^ keyPair, KeyUsage keyUsage, KeyFlags keyFlags) override;

		// удалить пару ключей
		public: virtual void DeleteKeyPair(array<BYTE>^ keyID) override
		{
			// операция не поддерживается
			throw gcnew NotSupportedException();
		}
		// удалить все ключи
		public: virtual void DeleteKeys() override;

		///////////////////////////////////////////////////////////////////////
		// Выполнение операции с личным ключом контейнера
		///////////////////////////////////////////////////////////////////////

		// получить описатель ключевой пары
		public protected: virtual KeyHandle^ GetUserKey(array<BYTE>^ keyID, DWORD% keyType)
		{
			// получить описатель ключевой пары
			keyType = keyID[0]; return Handle->GetUserKey(keyType); 
		}
		// сгенерировать ключ
		public protected: virtual KeyHandle^ GenerateKeyPair(
			IntPtr hwnd, ALG_ID algID, DWORD flags
		);
		// импортировать ключ
		public protected: KeyHandle^ ImportKey(
			KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags
		);
		// экспортировать ключ
		public protected: array<BYTE>^ ExportKey(
			KeyHandle^ hKey, KeyHandle^ hExportKey, DWORD exportType, DWORD flags
		);
		// расшифровать данные
		public protected: array<BYTE>^ Decrypt(
			KeyHandle^ hKey, array<BYTE>^ data, DWORD flags
		);
		// подписать хэш-значение
		public protected: array<BYTE>^ SignHash(
			DWORD keyType, HashHandle^ hHash, DWORD flags
		); 
	};
}}}