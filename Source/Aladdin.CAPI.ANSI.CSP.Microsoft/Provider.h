#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� 
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CSP::Provider
	{
		// �����������
		protected: Provider(DWORD type, String^ name, bool sspi) : CAPI::CSP::Provider(type, name, sspi) {} 

		// �������� ��������� �� ���������
		public: virtual CAPI::Culture^ GetCulture(SecurityStore^ scope, String^ keyOID) override
        {
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// �������� ��������� �� ���������
			return factory.Get()->GetCulture(scope, keyOID); 
		}
		// �������� ��������� �� ���������
		public: virtual PBE::PBECulture^ GetCulture(PBE::PBEParameters^ parameters, String^ keyOID) override
        {
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// �������� ��������� �� ���������
			return factory.Get()->GetCulture(parameters, keyOID); 
		}
		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override
		{
			// ������� ������� �������
			return ANSI::Factory::RedirectAlgorithm(outer, scope, parameters, type); 
		}
	}; 
}}}}}
