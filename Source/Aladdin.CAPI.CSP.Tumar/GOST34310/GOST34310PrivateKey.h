#pragma once
using namespace System::Diagnostics::CodeAnalysis;

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace GOST34310
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ���� 
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::GOST::GOSTR3410::IECPrivateKey
	{
		// �����������
		public: PrivateKey(CAPI::CSP::Provider^ provider, SecurityObject^ scope, 
			CAPI::GOST::GOSTR3410::IECPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID, DWORD keyType)

			// ��������� ���������� ���������
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, keyType) {}
		
		// ��������� ��������
		public: virtual property Math::BigInteger^ D { 
			
			// ��������� ����������
			[SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
			Math::BigInteger^ get() { throw gcnew InvalidKeyException(); }
		}	
	};
}}}}}
