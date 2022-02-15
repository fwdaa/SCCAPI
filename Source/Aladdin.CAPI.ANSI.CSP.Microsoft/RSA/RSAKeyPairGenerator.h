#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA
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
				// ��������� ����������
				throw gcnew NotSupportedException(); 
			}
		}
		// ������������� ���� ������
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
			String^ keyOID, DWORD keyType, DWORD keyFlags) override 
		{
			// ���������� ����� �����
			int bits = ((ANSI::RSA::IParameters^)Parameters)->KeySize;

			// ������� ���� ������
			return Generate(container, keyType, (bits << 16) | keyFlags); 
		}
	};
}}}}}}