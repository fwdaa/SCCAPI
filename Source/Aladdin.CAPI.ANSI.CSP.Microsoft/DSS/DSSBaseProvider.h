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

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
