#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace AKS 
{
	///////////////////////////////////////////////////////////////////////////
	// Контейнер на смарт-карте
	///////////////////////////////////////////////////////////////////////////
	public ref class Container : CAPI::CSP::Container
	{
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
			: CAPI::CSP::Container(store, name, mode) {}

		// установить признак использования по умолчанию
		public: virtual void SetDefaultStoreContainer() override
		{
			// установить признак использования по умолчанию
			Handle->SetLong(0x10004, 1, 0);
		} 
	}; 
}}}}}
