#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace X942
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ DH
	///////////////////////////////////////////////////////////////////////////
	public ref class NPrivateKey : CAPI::CNG::NPrivateKey, CAPI::ANSI::X942::IPrivateKey
	{
		// конструктор
		public: NPrivateKey(CAPI::CNG::NProvider^ provider, SecurityObject^ scope, 
			CAPI::ANSI::X942::IPublicKey^ publicKey, CAPI::CNG::NKeyHandle^ hPrivateKey) 
			: CAPI::CNG::NPrivateKey(provider, scope, publicKey, hPrivateKey) {} 

		// секретное значение
		public: virtual property Math::BigInteger^ X { Math::BigInteger^ get() 
		{ 
			// вернуть секретное значение 
			return (x != nullptr) ? x : (GetPrivateValue(), x); 
		}}	
		// определить секретное значение
		private: void GetPrivateValue(); private: Math::BigInteger^ x;
	};
}}}}}}

