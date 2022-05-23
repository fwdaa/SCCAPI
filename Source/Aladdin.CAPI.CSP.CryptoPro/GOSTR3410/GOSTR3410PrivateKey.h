#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ 
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::GOST::GOSTR3410::IECPrivateKey
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian;

		// конструктор
		public: PrivateKey(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, GOST::GOSTR3410::IECPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID, DWORD keyType)

			// сохранить переданные параметры
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, keyType) {} 

		// секретное значение
		public: virtual property Math::BigInteger^ D { Math::BigInteger^ get() 
		{ 
			// вернуть секретное значение 
			return (d != nullptr) ? d : (GetPrivateValue(), d); 
		}}	
		// определить секретное значение
		private: void GetPrivateValue(); private: Math::BigInteger^ d;
	};
}}}}}
