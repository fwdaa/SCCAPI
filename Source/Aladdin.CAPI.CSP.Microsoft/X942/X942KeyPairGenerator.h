#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace X942
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������ DH
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// �����������
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, CAPI::ANSI::X942::IParameters^ parameters) 

			// ��������� ���������� ���������
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) {} 

		// ������������� ���� ������
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
			String^ keyOID, DWORD keyType, DWORD keyFlags) override; 
	};
}}}}}
