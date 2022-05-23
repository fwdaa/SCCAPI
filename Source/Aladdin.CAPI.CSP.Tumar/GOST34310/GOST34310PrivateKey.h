#pragma once
using namespace System::Diagnostics::CodeAnalysis;

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace GOST34310
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ 
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::GOST::GOSTR3410::IECPrivateKey
	{
		// конструктор
		public: PrivateKey(CAPI::CSP::Provider^ provider, SecurityObject^ scope, 
			CAPI::GOST::GOSTR3410::IECPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID, DWORD keyType)

			// сохранить переданные параметры
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, keyType) {}
		
		// секретное значение
		public: virtual property Math::BigInteger^ D { 
			
			// выбросить исключение
			[SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
			Math::BigInteger^ get() { throw gcnew InvalidKeyException(); }
		}	
	};
}}}}}
