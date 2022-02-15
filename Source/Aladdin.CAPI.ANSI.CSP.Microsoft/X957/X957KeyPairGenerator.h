#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace X957
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������ DSA
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// �����������
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, CAPI::ANSI::X957::IParameters^ parameters) 

			// ��������� ���������� ���������
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) {} 

		// ������������� ���� ������
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
			String^ keyOID, DWORD keyType, DWORD keyFlags) override; 
	};
}}}}}}
