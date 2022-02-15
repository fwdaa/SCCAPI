#pragma once
#include "DSSProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace DSS 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Base DSS and Diffie-Hellman
	///////////////////////////////////////////////////////////////////////////
	public ref class BaseProvider : Provider
	{
		// �����������
		public: BaseProvider() : Provider(PROV_DSS_DH, MS_DEF_DSS_DH_PROV_W, false) {}

		// �����������
		protected: BaseProvider(DWORD type, String^ name, bool sspi) : Provider(type, name, sspi) {}

		// �������� ��������� �� ���������
		public: virtual CAPI::Culture^ GetCulture(SecurityStore^ scope, String^ keyOID) override
        {
			// �������� ��������� �� ���������
			return (gcnew ANSI::Factory())->GetCulture(scope, keyOID); 
		}
		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;
	}; 
}}}}}}
