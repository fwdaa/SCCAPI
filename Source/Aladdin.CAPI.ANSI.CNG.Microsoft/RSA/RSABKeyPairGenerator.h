#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace RSA
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyPairGenerator : CAPI::CNG::BKeyPairGenerator
	{
		// ��������� ���������
		private: ANSI::RSA::IParameters^ parameters; 

		// �����������
		public: BKeyPairGenerator(CAPI::Factory^ factory, SecurityObject^ scope, 
			IRand^ rand, String^ provider, ANSI::RSA::IParameters^ parameters) 
			
			// ��������� ���������� ���������
			: CAPI::CNG::BKeyPairGenerator(factory, scope, rand, provider, BCRYPT_RSA_ALGORITHM, 0) 
		 { 
			// ��������� �������� ����������
			if (parameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L))
			{
				// ��� ������ ��������� ����������
				throw gcnew NotSupportedException(); 
			}
			// ��������� ���������� ���������
			this->parameters = parameters; 
		} 
		// ������������� ���� ������
		public: virtual KeyPair^ Generate(String^ keyOID) override; 
	};
}}}}}}
