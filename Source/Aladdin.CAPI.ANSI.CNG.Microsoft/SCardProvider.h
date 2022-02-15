#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер для смарт-карт
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardProvider : Provider
	{
		// конструктор
		public: SCardProvider() : Provider("Microsoft Smart Card Key Storage Provider") {}

		// получить хранилище контейнера
		public: virtual array<String^>^ EnumerateStores(Scope scope) override 
		{ 
			// создать список имен
			return gcnew array<String^> { "Card" }; 
		}
		// получить хранилище контейнера
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// вернуть хранилище контейнеров
			return gcnew CAPI::CNG::SCardStores(this, scope, 0); 
		}
	};
}}}}}
