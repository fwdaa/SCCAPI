#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace X957
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ DSA
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::ANSI::X957::IPrivateKey
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// конструктор
		public: PrivateKey(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, CAPI::ANSI::X957::IPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID)

			// сохранить переданные параметры
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, AT_SIGNATURE) {} 

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
