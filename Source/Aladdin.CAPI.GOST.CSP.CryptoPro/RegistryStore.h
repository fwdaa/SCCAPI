#pragma once
#include "RegistryContainer.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Управление контейнерами в реестре
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CAPI::CSP::RegistryStore
	{
		// конструктор
		public: static RegistryStore^ Create(CAPI::CSP::Provider^ provider, CAPI::Scope scope) 
		{
			// создать объект смарт-карты
			RegistryStore^ regStore = gcnew RegistryStore(provider, scope); 

			// вернуть прокси
			try { return (RegistryStore^)Proxy::SecurityObjectProxy::Create(regStore); }

			// обработать возможную ошибку
			catch (Exception^) { delete regStore; throw; }
		}
		// конструктор
		protected: RegistryStore(CAPI::CSP::Provider^ provider, CAPI::Scope scope)

			// сохранить переданные параметры
            : CAPI::CSP::RegistryStore(provider, scope, RegistryContainer::typeid, 0) {} 

        // допустимые типы дочерних объектов
        public: virtual array<Type^>^ GetChildAuthenticationTypes(String^ user) override
        {
            // указать допустимые типы аутентификации
			return gcnew array<Type^> { Auth::PasswordCredentials::typeid, nullptr }; 
        } 
		// полное имя контейнера
		public: virtual String^ GetNativeContainerName(String^ name) override
		{
			// сформировать полное имя контейнера
			return String::Format("\\\\.\\{0}\\{1}", "REGISTRY", name); 
		}
		// перечисление контейнеров
		public: virtual array<String^>^ EnumerateObjects() override; 

		// создать контейнер
		public: virtual CAPI::SecurityObject^ CreateObject(IRand^ rand, Object^ name, 
			Object^ authenticationData, ...array<Object^>^ parameters) override; 
		// удалить контейнер
		public: virtual void DeleteObject(Object^ name, 
			array<CAPI::Authentication^>^ authentications) override; 
	}; 
}}}}}
