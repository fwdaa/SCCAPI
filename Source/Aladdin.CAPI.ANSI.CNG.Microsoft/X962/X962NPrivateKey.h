#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace X962
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ DH
	///////////////////////////////////////////////////////////////////////////
	public ref class NPrivateKey : CAPI::CNG::NPrivateKey, CAPI::ANSI::X962::IPrivateKey
	{
		// конструктор
		public: NPrivateKey(CAPI::CNG::NProvider^ provider, SecurityObject^ scope, 
			CAPI::ANSI::X962::IPublicKey^ publicKey, CAPI::CNG::NKeyHandle^ hPrivateKey) 
			: CAPI::CNG::NPrivateKey(provider, scope, publicKey, hPrivateKey) {} 

		// секретное значение
		public: virtual property Math::BigInteger^ D { Math::BigInteger^ get() 
		{ 
			// вернуть секретное значение 
			return (d != nullptr) ? d : (GetPrivateValue(), d); 
		}}	
		// определить секретное значение
		private: void GetPrivateValue(); private: Math::BigInteger^ d;
	};
}}}}}}
