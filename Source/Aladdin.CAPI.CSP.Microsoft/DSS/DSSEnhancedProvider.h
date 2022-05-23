#pragma once
#include "DSSBaseProvider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace DSS 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Enhanced DSS and Diffie-Hellman
	///////////////////////////////////////////////////////////////////////////
	public ref class EnhancedProvider : BaseProvider
	{
		// �����������
		public: EnhancedProvider() : BaseProvider(PROV_DSS_DH, MS_ENH_DSS_DH_PROV_W, false) {}

		// �����������
		protected: EnhancedProvider(DWORD type, String^ name, bool sspi) 
		
			// ��������� ���������� ���������
			: BaseProvider(type, name, sspi) {}

		// ���������� ��� �����
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override; 

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}
