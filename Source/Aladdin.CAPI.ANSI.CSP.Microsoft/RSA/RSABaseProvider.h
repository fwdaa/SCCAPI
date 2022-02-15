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
		public: BaseProvider() : Provider(PROV_RSA_FULL, MS_DEF_PROV_W, false, true) {}

		// �����������
		protected: BaseProvider(DWORD type, String^ name, bool sspi, bool oaep) 

			// ��������� ���������� ���������
			: Provider(type, name, sspi, oaep) {}

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
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;
	}; 
}}}}}}
