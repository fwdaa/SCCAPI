#pragma once
#include "SCardStore.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Смарт-карты как устройство хранения
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStores : CAPI::CSP::SCardStores
	{
		// конструктор
		public: SCardStores(CAPI::CSP::Provider^ provider, CAPI::Scope scope)

			// сохранить переданные параметры
			: CAPI::CSP::SCardStores(provider, scope, 0) {}

		// открыть контейнер 
		public: virtual SecurityObject^ OpenObject(Object^ name, FileAccess access) override
		{
			// вернуть смарт-карту
			return SCardStore::Create(this, name->ToString()); 
		}
	};
}}}}}
