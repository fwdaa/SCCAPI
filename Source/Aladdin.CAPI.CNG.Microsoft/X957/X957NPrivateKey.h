#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace X957
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ���� DSA
	///////////////////////////////////////////////////////////////////////////
	public ref class NPrivateKey : CAPI::CNG::NPrivateKey, CAPI::ANSI::X957::IPrivateKey
	{
		// �����������
		public: NPrivateKey(CAPI::CNG::NProvider^ provider, SecurityObject^ scope, 
			CAPI::ANSI::X957::IPublicKey^ publicKey, CAPI::CNG::NKeyHandle^ hPrivateKey) 
			: CAPI::CNG::NPrivateKey(provider, scope, publicKey, hPrivateKey) {} 

		// ��������� ��������
		public: virtual property Math::BigInteger^ X { Math::BigInteger^ get() 
		{ 
			// ������� ��������� �������� 
			return (x != nullptr) ? x : (GetPrivateValue(), x); 
		}}	
		// ���������� ��������� ��������
		private: void GetPrivateValue(); private: Math::BigInteger^ x;
	};
}}}}}
