#pragma once
#include "Handle.h"
#include "Store.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический контейнер
	///////////////////////////////////////////////////////////////////////////
	public ref class Container : CAPI::Container
	{
		// список ключей контейнера и режим открытия 
		private: Using<NKeyHandle^> hKeyPair; private: DWORD keyType; private: DWORD mode; 

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
		protected: Container(ProviderStore^ store, String^ name, DWORD mode); 
		// деструктор
		public: virtual ~Container();  

        // криптографический провайдер
        public: property NProvider^ Provider 
		{ 
			// криптографический провайдер
			NProvider^ get() new { return Store->Provider; } 
		} 
        // хранилище контейнера
        public: property ProviderStore^ Store 
        {
            // хранилище контейнера
            ProviderStore^ get() new { return (ProviderStore^)CAPI::Container::Store; }
        }
		// режим открытия контейнера
        protected: property DWORD Mode { DWORD get() { return mode; }}

		// описатель ключа
		public: property NKeyHandle^ Handle { NKeyHandle^ get() { return hKeyPair.Get(); }}
		// тип ключа
		public: property DWORD KeyType { DWORD get() { return keyType; }}

		///////////////////////////////////////////////////////////////////////
		// Управление аутентификацией
		///////////////////////////////////////////////////////////////////////

		// проверить необходимость аутентификации
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
				return gcnew PasswordService(this, nullptr); 
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
		///////////////////////////////////////////////////////////////////////
		// Поиск объектов
		///////////////////////////////////////////////////////////////////////

		// получить идентификатор для нового ключа
		public protected: array<BYTE>^ GetKeyID(KeyUsage keyUsage); 

		// перечислить идентификаторы ключей
		public: virtual array<array<BYTE>^>^ GetKeyIDs() override; 

		// получить идентификатор по значению ключа
		public: virtual array<array<BYTE>^>^ GetKeyIDs(ASN1::ISO::PKIX::SubjectPublicKeyInfo^ keyInfo) override; 

		// вернуть открытый ключ
		public: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ GetPublicKeyInfo(array<BYTE>^ keyID); 

		// вернуть открытый ключ
		public: virtual IPublicKey^ GetPublicKey(array<BYTE>^ keyID) override; 

		// вернуть личный ключ
		public: virtual IPrivateKey^ GetPrivateKey(array<BYTE>^ keyID) override; 

		///////////////////////////////////////////////////////////////////////
		// Управление сертификатами
		///////////////////////////////////////////////////////////////////////

		// получить сертификат открытого ключа
		public: virtual Certificate^ GetCertificate(array<BYTE>^ keyID) override; 

		// сохранить сертификат открытого ключа
		public: virtual void SetCertificate(
			array<BYTE>^ keyID, Certificate^ certificate) override; 

		// сохранить пару ключей
		public: virtual array<BYTE>^ SetKeyPair(IRand^ rand, 
			KeyPair^ keyPair, KeyUsage keyUsage, KeyFlags keyFlags) override;

		// удалить пару ключей
		public: virtual void DeleteKeyPair(array<BYTE>^ keyID) override;

		// удалить ключи контейнера
		public: virtual void DeleteKeys() override;

		///////////////////////////////////////////////////////////////////////
		// Выполнение операции с личным ключом контейнера
		///////////////////////////////////////////////////////////////////////

		// установить параметры ключевой пары
		private: void CompleteGenerateKeyPair(IntPtr hwnd, 
			BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags
        );
		// сгенерировать пару ключей
		public protected: NKeyHandle^ GenerateKeyPair(IntPtr hwnd, 
			String^ alg, DWORD keyType, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags
        );
		// импортировать ключ
		public protected: NKeyHandle^ ImportKeyPair(IntPtr hwnd,
			NKeyHandle^ hKey, DWORD keyType, String^ typeBlob, IntPtr ptrBlob, 
			DWORD cbBlob, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags
		);
		// экспортировать ключ
		public protected: array<BYTE>^ ExportKey(
			NKeyHandle^ hKey, NKeyHandle^ hExportKey, String^ blobType, DWORD flags
        );
		// выполнить согласование общего ключа
		public protected: NSecretHandle^ AgreementSecret(
			NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey, DWORD flags
		);
		// расшифровать данные
		public protected: array<BYTE>^ Decrypt(
			NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ data, DWORD flags
        );
		// подписать хэш-значение
		public protected: array<BYTE>^ SignHash(
			NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ hash, DWORD flags
        ); 
	};
}}}