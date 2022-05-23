#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� 
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CSP::Provider
	{
		// �����������
		protected: Provider(DWORD type, String^ name, bool sspi) : CAPI::CSP::Provider(type, name, sspi) {} 

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override
		{
			// ������� ������� �������
			return ANSI::Factory::RedirectAlgorithm(outer, scope, oid, parameters, type); 
		}
	}; 
}}}}
