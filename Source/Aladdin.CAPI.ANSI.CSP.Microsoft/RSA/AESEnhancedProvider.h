#pragma once
#include "RSAStrongProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� AES
	///////////////////////////////////////////////////////////////////////////
	public ref class AESEnhancedProvider : StrongProvider
	{
		// �����������
		public: AESEnhancedProvider() : StrongProvider(PROV_RSA_AES, nullptr, false, true)
		{
			// ��������� ������ ������ ����������� ������
			SecretKeyFactories()->Add("AES", gcnew Keys::AES()); 
		}
		// �����������
		protected: AESEnhancedProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// ��������� ���������� ���������
			: StrongProvider(type, name, sspi, oaep) 
		{
			// ��������� ������ ������ ����������� ������
			SecretKeyFactories()->Add("AES", gcnew Keys::AES()); 
		}
		// ��� ������
		public: virtual property String^ Group { String^ get() override { return Name; }}

		// ��� ����������
		public: virtual property String^ Name { String^ get() override
		{
			// ������� ��� ����������
			return "Microsoft Enhanced RSA and AES Cryptographic Provider"; 
		}}
		// ������� ��� �����
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override;

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
