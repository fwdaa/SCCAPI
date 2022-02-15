#pragma once
#include "RSAEnhancedProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	//  риптопровайдер Strong Cryptographic Provider
	///////////////////////////////////////////////////////////////////////////
	public ref class StrongProvider : EnhancedProvider
	{
		// конструктор
		public: StrongProvider() : EnhancedProvider(PROV_RSA_FULL, MS_STRONG_PROV_W, false, true) {}

		// конструктор
		protected: StrongProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// сохранить переданные параметры
			: EnhancedProvider(type, name, sspi, oaep) {}

		// им€ провайдера
		public: virtual property String^ Name { String^ get() override { return Provider::Name; }}
	}; 
}}}}}}
