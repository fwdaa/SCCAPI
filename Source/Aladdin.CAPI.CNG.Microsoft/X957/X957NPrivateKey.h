#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace X957
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ DSA
	///////////////////////////////////////////////////////////////////////////
	public ref class NPrivateKey : CAPI::CNG::NPrivateKey, CAPI::ANSI::X957::IPrivateKey
	{
		// конструктор
		public: NPrivateKey(CAPI::CNG::NProvider^ provider, SecurityObject^ scope, 
			CAPI::ANSI::X957::IPublicKey^ publicKey, CAPI::CNG::NKeyHandle^ hPrivateKey) 
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
}}}}}
