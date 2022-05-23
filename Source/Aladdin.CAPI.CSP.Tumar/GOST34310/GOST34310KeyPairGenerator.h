#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace GOST34310
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// �����������
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, INamedParameters^ parameters)

			// ��������� ���������� ���������
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) {}

		// ������������� ���� ������
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
            String^ keyOID, DWORD keyType, DWORD keyFlags) override; 
	};
}}}}}
