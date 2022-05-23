#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace RSA
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// �����������
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, ANSI::RSA::IParameters^ parameters)

			// ��������� ���������� ���������
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) 
		{
			// ��������� �������� ����������
			if (parameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) 
			{
				// ��� ������ ��������� ����������
				throw gcnew NotSupportedException(); 
			}
		}
		// ������������� ���� ������
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
			String^ keyOID, DWORD keyType, DWORD keyFlags) override;  
	};
}}}}}
