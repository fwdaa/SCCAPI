#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический контейнер
	///////////////////////////////////////////////////////////////////////////
	public ref class Container : CAPI::CSP::Container
	{
		// родное имя контейнера
		private: String^ nativeName; 

        // конструктор
		public: static Container^ Create(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
		{
			// создать объект контейнера
			Container^ container = gcnew Container(store, name, mode); 

			// вернуть прокси
			try { return (Container^)Proxy::SecurityObjectProxy::Create(container); }

			// обработать возможную ошибку
			catch (Exception^) { delete container; throw; } 
		}
		// конструктор
		protected: Container(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
			
			// сохранить переданные параметры
			: CAPI::CSP::Container(store, name, mode) 
		{
			// указать родное имя контейнера
			nativeName = store->GetNativeContainerName(name); 
		} 
		// уникальное имя хранилища
		public: virtual String^ GetUniqueID() override; 

		///////////////////////////////////////////////////////////////////////////
		// Установка активного ключа для контейнера
		///////////////////////////////////////////////////////////////////////////
		public protected: ref class SetActivePrivateKey 
		{
			// описатель контейнера и идентификатор активного ключа
			private: CAPI::CSP::ContainerHandle^ hContainer; array<BYTE>^ keyID; 

			// конструктор
			public: SetActivePrivateKey(Container^ container, CAPI::CSP::PrivateKey^ privateKey); 
			// деструктор
			public: virtual ~SetActivePrivateKey(); 
		};
		/////////////////////////////////////////////////////////////////////////////
		// Поддержка аутентификации
		/////////////////////////////////////////////////////////////////////////////
		private: ref class PasswordService : Auth::PasswordService
		{
			// конструктор
			public: PasswordService(Container^ store) : Auth::PasswordService(store, "USER") {}
        
			// установить аутентификационные данные
			protected: virtual void SetPassword(String^ password) override
			{
				// установить пароль контейнера
				((Container^)Target)->SetPassword(password);
			}
		}; 
		// проверить наличие исключения аутентификации
		public: virtual bool IsAuthenticationRequired(Exception^ e) override; 

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
				return gcnew PasswordService(this); 
			}				
			return nullptr; 
		}
		// установить пароль контейнера
		private: void SetPassword(String^ password); 

		///////////////////////////////////////////////////////////////////////
		// Управление ключами
		///////////////////////////////////////////////////////////////////////

		// получить описатель ключевой пары
		public protected: virtual CAPI::CSP::KeyHandle^ GetUserKey(
			array<BYTE>^ keyID, DWORD% keyType) override; 

		// получить тип для нового ключа
		public protected: virtual DWORD GetKeyType(
			String^ keyOID, KeyUsage keyUsage) override; 

		// перечислить идентификаторы ключей
		public: virtual array<array<BYTE>^>^ GetKeyIDs() override; 

		// удалить пару ключей
		public: virtual void DeleteKeyPair(array<BYTE>^ keyID) override; 
		// удалить все ключи
		public: virtual void DeleteKeys() override;

		///////////////////////////////////////////////////////////////////////
		// Выполнение операции с личным ключом контейнера
		///////////////////////////////////////////////////////////////////////

		// импортировать ключ
		public protected: CAPI::CSP::KeyHandle^ ImportKey(
			CAPI::CSP::KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags)
		{
			// импортировать ключ
			return CAPI::CSP::Container::ImportKey(hImportKey, ptrBlob, cbBlob, flags); 
		}
		// экспортировать ключ
		public protected: array<BYTE>^ ExportKey(
			CAPI::CSP::KeyHandle^ hKey, CAPI::CSP::KeyHandle^ hExportKey, DWORD exportType, DWORD flags)
		{
			// экспортировать ключ
			return CAPI::CSP::Container::ExportKey(hKey, hExportKey, exportType, flags); 
		}
	}; 
}}}}
