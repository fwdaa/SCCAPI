#pragma once
#include "RSABaseProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Enhanced Cryptographic Provider
	///////////////////////////////////////////////////////////////////////////
	public ref class EnhancedProvider : BaseProvider
	{
		// �����������
		public: EnhancedProvider() : BaseProvider(PROV_RSA_FULL, MS_ENHANCED_PROV_W, false, true) {}

		// �����������
		protected: EnhancedProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// ��������� ���������� ���������
			: BaseProvider(type, name, sspi, oaep) {}

		// ��� ����������
		public: virtual property String^ Name { String^ get() override 
		{ 
			// ��� ����������
			return "Microsoft Enhanced Cryptographic Provider"; 
		}}
		// ���������� ��� �����
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override; 

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
