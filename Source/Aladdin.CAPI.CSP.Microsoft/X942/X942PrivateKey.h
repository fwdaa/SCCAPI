#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace X942
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ DH
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::ANSI::X942::IPrivateKey
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// конструктор
		public: PrivateKey(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, CAPI::ANSI::X942::IPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID)

			// сохранить переданные параметры
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, AT_KEYEXCHANGE) {} 

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
