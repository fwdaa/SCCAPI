#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Управление контейнерами на смарт-карте
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : CAPI::CSP::ProviderStore
	{
        // описатель смарт-карты и апплет на смарт-карте
		private: Using<CAPI::CSP::StoreHandle^> handle; BOOL destroy; SecurityObject^ applet; 

		// конструктор
		public: static SCardStore^ Create(SecurityStore^ store, String^ name) 
		{
			// создать объект смарт-карты
			SCardStore^ cardStore = gcnew SCardStore(store, name); 

			// вернуть прокси
			try { return (SCardStore^)Proxy::SecurityObjectProxy::Create(cardStore); }

			// обработать возможную ошибку
			catch (Exception^) { delete cardStore; throw; }
		}
		// конструктор
		protected: SCardStore(SecurityStore^ store, String^ name); 
		// деструктор
		public: virtual ~SCardStore();  

		// описатель смарт-карты
		public: property CAPI::CSP::StoreHandle^ Handle 
		{ 
			// описатель смарт-карты
			CAPI::CSP::StoreHandle^ get() { return handle.Get(); }
		}
		// признак наличия аутентификации
		public: virtual property bool HasAuthentication { bool get() override { return true; }}

        // доступные типы аутентификации
        public: virtual array<Type^>^ GetAuthenticationTypes(String^ user) override; 
		// получить сервис аутентификации
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override; 

		// выполнить аутентификацию
		public: virtual array<Credentials^>^ Authenticate() override; 

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

		// полное имя контейнера
		public: virtual String^ GetNativeContainerName(String^ name) override
		{
			// сформировать полное имя контейнера
			return String::Format("\\\\.\\{0}\\{1}", Name, name); 
		}
		// перечисление контейнеров
		public: virtual array<String^>^ EnumerateObjects() override; 

		// создать контейнер
		public: virtual CAPI::SecurityObject^ CreateObject(IRand^ rand, 
			Object^ name, Object^ authenticationData, ...array<Object^>^ parameters) override; 
		// удалить контейнер
		public: virtual void DeleteObject(Object^ name, 
			array<CAPI::Authentication^>^ authentications) override; 

		// установить признак использования по умолчанию
		public: virtual void SetDefaultContainer(CAPI::CSP::Container^ container)
		{
			// установить признак использования по умолчанию
			container->Handle->SetLong(PP_CONTAINER_DEFAULT, 0, 0);
		} 
	};
}}}}
