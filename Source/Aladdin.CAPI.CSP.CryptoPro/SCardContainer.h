#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический контейнер на смарт-карте
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardContainer : Container
	{
        // конструктор
		public: static SCardContainer^ Create(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
		{
			// создать объект контейнера
			SCardContainer^ container = gcnew SCardContainer(store, name, mode); 

			// вернуть прокси
			try { return (SCardContainer^)Proxy::SecurityObjectProxy::Create(container); }

			// обработать возможную ошибку
			catch (Exception^) { delete container; throw; }
		}
		// конструктор
		protected: SCardContainer(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
			
			// сохранить переданные параметры
			: Container(store, name, mode) {}

		// установить признак использования по умолчанию
		public: virtual void SetDefaultStoreContainer() override
		{
			// установить признак использования по умолчанию
			Handle->SetLong(PP_CONTAINER_DEFAULT, 0, 0);
		} 
	}; 
}}}}
