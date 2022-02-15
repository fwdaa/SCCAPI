#pragma once

using namespace System::IO; 

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// Управление контейнерами
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : CAPI::CSP::ProviderStore
	{
		// общий кэш-паролей
		private: static AuthenticationCache^ Cache = gcnew AuthenticationCache(false); 

		// конструктор
		public: SCardStore(CAPI::CSP::Provider^ provider) 
            : CAPI::CSP::ProviderStore(provider, CAPI::KeyFlags::None, Cache) {} 
	};
}}}}}