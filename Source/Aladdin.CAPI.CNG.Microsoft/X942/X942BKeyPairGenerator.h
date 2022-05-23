#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace X942
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyPairGenerator : CAPI::CNG::BKeyPairGenerator
	{
		// �����������
		public: BKeyPairGenerator(CAPI::Factory^ factory, SecurityObject^ scope, 
			IRand^ rand, String^ provider, ANSI::X942::IParameters^ parameters) 
			
			// ��������� ���������� ���������
			: CAPI::CNG::BKeyPairGenerator(factory, scope, rand, provider, BCRYPT_DH_ALGORITHM, 0) 
		 
			// ��������� ���������� ���������
			{ this->parameters = parameters; } private: ANSI::X942::IParameters^ parameters; 

		// ������������� ���� ������
		public: virtual KeyPair^ Generate(String^ keyOID) override; 
	};
}}}}}

