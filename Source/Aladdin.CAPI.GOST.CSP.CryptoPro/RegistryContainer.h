#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический контейнер в реестре
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryContainer : Container
	{
        // конструктор
		public: static RegistryContainer^ Create(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
		{
			// создать объект контейнера
			RegistryContainer^ container = gcnew RegistryContainer(store, name, mode); 

			// вернуть прокси
			try { return (RegistryContainer^)Proxy::SecurityObjectProxy::Create(container); }

			// обработать возможную ошибку
			catch (Exception^) { delete container; throw; }
		}
		// конструктор
		protected: RegistryContainer(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
			
			// сохранить переданные параметры
			: Container(store, name, mode) {}

		// вернуть протокол аутентификации
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override; 
	}; 
}}}}}
