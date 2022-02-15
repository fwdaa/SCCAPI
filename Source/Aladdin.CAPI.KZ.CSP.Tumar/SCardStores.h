#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar 
{
	///////////////////////////////////////////////////////////////////////////
	// Смарт-карты как устройство хранения
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStores : CAPI::CSP::ProviderStore
	{
		// конструктор
		public: SCardStores(CAPI::CSP::Provider^ provider, CAPI::Scope scope)

			// сохранить переданные параметры
			: CAPI::CSP::ProviderStore(provider, scope, "Card", Container::typeid, 0) {}

		// признак отсутствия аутентификации
		public: virtual property bool HasAuthentication { bool get() override { return false; }}

		// определить имя контейнера для провайдера
		public: virtual String^ GetNativeContainerName(String^ name) override; 
		// перечисление контейнеров
		public: virtual array<String^>^ EnumerateObjects() override; 

		// создать объект
		public: virtual SecurityObject^ CreateObject(IRand^ rand, 
			Object^ name, Object^ authenticationData, ...array<Object^>^ parameters) override
        {
            // операция не поддерживается
            throw gcnew InvalidOperationException(); 
        }
        // удалить объект
		public: virtual void DeleteObject(Object^ name, 
			array<CAPI::Authentication^>^ authentications) override
        {
            // операция не поддерживается
            throw gcnew InvalidOperationException(); 
        }
	};
}}}}}
