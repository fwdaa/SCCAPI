#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Athena 
{
	///////////////////////////////////////////////////////////////////////////
	// Смарт-карта как устройство хранения
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : CAPI::CSP::SCardStore
	{
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
		protected: SCardStore(SecurityStore^ store, String^ name) 
			
			// сохранить переданные параметры
			: CAPI::CSP::SCardStore(store, Athena::Container::typeid, name, 0) {} 
	};
}}}}
