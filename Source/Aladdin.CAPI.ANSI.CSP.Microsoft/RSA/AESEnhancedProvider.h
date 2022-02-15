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
		public: AESEnhancedProvider() : StrongProvider(PROV_RSA_AES, nullptr, false, true) {}

		// �����������
		protected: AESEnhancedProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// ��������� ���������� ���������
			: StrongProvider(type, name, sspi, oaep) {}

		// ��� ������
		public: virtual property String^ Group { String^ get() override { return Name; }}

		// ��� ����������
		public: virtual property String^ Name { String^ get() override
		{
			// ������� ��� ����������
			return "Microsoft Enhanced RSA and AES Cryptographic Provider"; 
		}}
		// �������������� ������� ����������� ������
		public: virtual array<SecretKeyFactory^>^ SecretKeyFactories() override
		{
			// �������������� ������� ����������� ������
			return gcnew array<SecretKeyFactory^> { 
				ANSI::Keys::RC2 ::Instance, ANSI::Keys::RC4 ::Instance, 
				ANSI::Keys::DES ::Instance, ANSI::Keys::DESX::Instance, 
				ANSI::Keys::TDES::Instance, ANSI::Keys::AES ::Instance 
			}; 
		}
		// ������� ��� �����
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override;

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;
	}; 
}}}}}}
