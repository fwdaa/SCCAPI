#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический контейнер
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

		// сгенерировать ключ
		public protected: virtual CAPI::CSP::KeyHandle^ GenerateKeyPair(
			IntPtr hwnd, ALG_ID keyType, DWORD flags) override;

		// удалить ключи контейнера
		public: virtual void DeleteKeys() override
		{
			// удалить ключи контейнера и создать пустой контейнер
			CAPI::CSP::Container::DeleteKeys(); Synchronize(); 
		}
		// удалить контейнер
		public: void Delete() { Handle->SetParam(PP_DELETE_KEYSET, IntPtr::Zero, 0); }

		// выполнить синхронизацию
		public: void Synchronize() { Handle->GetLong(PP_HCRYPTPROV, 0); }
	}; 
}}}}}
