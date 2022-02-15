#pragma once
#include "RegistryContainer.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ���������� ������������ � �������
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CAPI::CSP::RegistryStore
	{
		// �����������
		public: static RegistryStore^ Create(CAPI::CSP::Provider^ provider, CAPI::Scope scope) 
		{
			// ������� ������ �����-�����
			RegistryStore^ regStore = gcnew RegistryStore(provider, scope); 

			// ������� ������
			try { return (RegistryStore^)Proxy::SecurityObjectProxy::Create(regStore); }

			// ���������� ��������� ������
			catch (Exception^) { delete regStore; throw; }
		}
		// �����������
		protected: RegistryStore(CAPI::CSP::Provider^ provider, CAPI::Scope scope)

			// ��������� ���������� ���������
            : CAPI::CSP::RegistryStore(provider, scope, RegistryContainer::typeid, 0) {} 

        // ���������� ���� �������� ��������
        public: virtual array<Type^>^ GetChildAuthenticationTypes(String^ user) override
        {
            // ������� ���������� ���� ��������������
			return gcnew array<Type^> { Auth::PasswordCredentials::typeid, nullptr }; 
        } 
		// ������ ��� ����������
		public: virtual String^ GetNativeContainerName(String^ name) override
		{
			// ������������ ������ ��� ����������
			return String::Format("\\\\.\\{0}\\{1}", "REGISTRY", name); 
		}
		// ������������ �����������
		public: virtual array<String^>^ EnumerateObjects() override; 

		// ������� ���������
		public: virtual CAPI::SecurityObject^ CreateObject(IRand^ rand, Object^ name, 
			Object^ authenticationData, ...array<Object^>^ parameters) override; 
		// ������� ���������
		public: virtual void DeleteObject(Object^ name, 
			array<CAPI::Authentication^>^ authentications) override; 
	}; 
}}}}}
