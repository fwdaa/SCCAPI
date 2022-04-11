#pragma once
#include "RSAProvider.h"
#include "..\RegistryStore.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Base Cryptographic Provider
	///////////////////////////////////////////////////////////////////////////
	public ref class BaseProvider : Provider
	{
		// �����������
		public: BaseProvider() : Provider(PROV_RSA_FULL, MS_DEF_PROV_W, false, true) 
		{
			// ��������� ������ ������ ����������� ������
			SecretKeyFactories()->Add("RC2" , gcnew Keys::RC2 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("RC4" , gcnew Keys::RC4 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("DES" , gcnew Keys::DES (                     )); 
			SecretKeyFactories()->Add("DESX", gcnew Keys::DESX(                     )); 
		}
		// �����������
		protected: BaseProvider(DWORD type, String^ name, bool sspi, bool oaep) 

			// ��������� ���������� ���������
			: Provider(type, name, sspi, oaep) 
		{
			// ��������� ������ ������ ����������� ������
			SecretKeyFactories()->Add("RC2" , gcnew Keys::RC2 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("RC4" , gcnew Keys::RC4 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("DES" , gcnew Keys::DES (                     )); 
			SecretKeyFactories()->Add("DESX", gcnew Keys::DESX(                     )); 
		}
		// ��� ������ �����������
		public: virtual property String^ Group { String^ get() override 
		{ 
			// ��� ������ �����������
			return "Microsoft Enhanced RSA and AES Cryptographic Provider"; 
		}}
		// ��� ����������
		public: virtual property String^ Name { String^ get() override 
		{ 
			// ��� ����������
			return "Microsoft Base Cryptographic Provider"; 
		}}
		// ����������� ��������� �����������
		public: virtual array<String^>^ EnumerateStores(Scope scope) override
		{
			// ������� ������ ����
			List<String^>^ names = gcnew List<String^>(); 

			// ������� ����� ��������
			if (scope == Scope::System) names->Add("HKLM"); 
			if (scope == Scope::User  ) names->Add("HKCU"); 

			// ������� ������ ����
			return names->ToArray(); 
		}
		// �������� ��������� ����������
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override
		{
			// ������� ��������� �����������
			return gcnew RegistryStore(this, scope);
		}
		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
