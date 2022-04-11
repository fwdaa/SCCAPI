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
		public: EnhancedProvider() : BaseProvider(PROV_RSA_FULL, MS_ENHANCED_PROV_W, false, true) 
		{
			// ��������� ������ ������ ����������� ������
			SecretKeyFactories()["RC2"] = gcnew Keys::RC2 (KeySizes::Range(5, 16)); 
			SecretKeyFactories()["RC4"] = gcnew Keys::RC4 (KeySizes::Range(5, 16)); 

			// ��������� ������ ������ ����������� ������
			SecretKeyFactories()->Add("DESede", gcnew Keys::TDES()); 
		}
		// �����������
		protected: EnhancedProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// ��������� ���������� ���������
			: BaseProvider(type, name, sspi, oaep) 
		{
			// ��������� ������ ������ ����������� ������
			SecretKeyFactories()["RC2"] = gcnew Keys::RC2 (KeySizes::Range(5, 16)); 
			SecretKeyFactories()["RC4"] = gcnew Keys::RC4 (KeySizes::Range(5, 16)); 

			// ��������� ������ ������ ����������� ������
			SecretKeyFactories()->Add("DESede", gcnew Keys::TDES()); 
		}
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
