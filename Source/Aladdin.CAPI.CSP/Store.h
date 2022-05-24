#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ��������� ��������������
	///////////////////////////////////////////////////////////////////////////
	public ref class PasswordService : Auth::PasswordService
	{
		// �����������
		public: PasswordService(SecurityObject^ obj, CSP::Handle^ handle) 
			
			// ��������� ���������� ���������
			: Auth::PasswordService(obj, "USER") 
        
			// ��������� ���������� ���������
			{ this->handle = handle; } private: Handle^ handle;

		// ��������� ����������
		protected: property CSP::Handle^ Handle { CSP::Handle^ get() { return handle; }}

		// ���������� ������������������ ������
		protected: virtual void SetPassword(String^ password) override
		{
			// ���������� ������ �� ���������
			handle->SetString(PP_KEYEXCHANGE_PIN, password, 0); 
		}
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��� ���������� �������� 
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderStore : ContainerStore
	{
		// ��� ������ ���������� � ����� ��������
		private: String^ name; private: Type^ containerType; private: DWORD mode;

		// �����������
		protected: ProviderStore(CSP::Provider^ provider, 
			CAPI::Scope scope, String^ name, Type^ containerType, DWORD mode) 
			
			// ��������� ���������� ���������
			: ContainerStore(provider, scope) 
		{ 
			// ��������� ���������� ���������
			this->name = name; this->containerType = containerType; this->mode = mode; 
		} 
		// �����������
		protected: ProviderStore(SecurityStore^ store, 
			String^ name, Type^ containerType, DWORD mode) : ContainerStore(store) 
		{ 
			// ��������� ���������� ���������
			this->name = name; this->containerType = containerType; this->mode = mode; 
		} 
        // ����������������� ���������
        public: property CSP::Provider^ Provider 
		{ 
			// ����������������� ���������
			CSP::Provider^ get() new { return (CSP::Provider^)ContainerStore::Provider; } 
		} 
		// ��� ���������
		public: virtual property Object^ Name { Object^ get() override sealed { return name; }}

		// ������ ���������� ����������
		protected: property DWORD Mode { DWORD get() { return mode; }}

		// ������� ������� ��������������
		public: virtual property bool HasAuthentication { bool get() { return false; }}
		// ��������� ������� ���������� ��������������
		public: virtual bool IsAuthenticationRequired(Exception^ e) override; 

		// ���������� ��� ���������� ��� ����������
		public: virtual String^ GetNativeContainerName(String^ name) { return name; }
		// ������������ �����������
		public: virtual array<String^>^ EnumerateObjects() override; 

		// ������� ���������
		public: virtual SecurityObject^ CreateObject(IRand^ rand, 
			Object^ name, Object^ authenticationData, ...array<Object^>^ parameters) override;
		// ������� ��������� 
		public: virtual SecurityObject^ OpenObject(
			Object^ name, FileAccess access) override; 
		// ������� ���������
		public: virtual void DeleteObject(
			Object^ name, array<CAPI::Authentication^>^ authentications) override; 

		// �������� ���������� ��������� �����
		public protected: virtual Certificate^ GetCertificate(
			KeyHandle^ hKeyPair, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo
		);
		// �������� ���� ������������
		public protected: virtual array<Certificate^>^ GetCertificateChain(Certificate^ certificate); 

		// ��������� ���������� ��������� �����
		public protected: virtual void SetCertificateChain(
			KeyHandle^ hKeyPair, array<Certificate^>^ certificateChain
		); 
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������� ����������� � �������
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : ProviderStore
	{
        // ��������� ���������
		private: StoreHandle^ handle; 

		// �����������
		public: RegistryStore(CSP::Provider^ provider, CAPI::Scope scope, Type^ containerType, DWORD mode);  
		// ����������
		public: virtual ~RegistryStore();   

		// ��������� ���������
		protected: property StoreHandle^ Handle { StoreHandle^ get() { return handle; }}
		// ������������ �����������
		public: virtual array<String^>^ EnumerateObjects() override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// �����-����� ��� ���������� ��������
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : ProviderStore
	{
        // ��������� �����-�����
		private: Using<StoreHandle^> handle; 

		// �����������
		public: static SCardStore^ Create(SecurityStore^ store, String^ name, DWORD mode) 
		{
			// ������� ������ �����-�����
			SCardStore^ cardStore = gcnew SCardStore(store, CSP::Container::typeid, name, mode); 

			// ������� ������
			try { return (SCardStore^)Proxy::SecurityObjectProxy::Create(cardStore); } 

			// ���������� ��������� ������
			catch (Exception^) { delete cardStore; throw; }
		}
		// �����������
		protected: SCardStore(SecurityStore^ store, Type^ containerType, String^ name, DWORD mode); 
		// ����������
		public: virtual ~SCardStore();  

		// ��������� �����-�����
		protected: property StoreHandle^ Handle { StoreHandle^ get() { return handle.Get(); }}

		// ������� ������� ��������������
		public: virtual property bool HasAuthentication { bool get() override { return true; }}

		// �������������� ���� ��������������
		public: virtual array<Type^>^ GetAuthenticationTypes(String^ user) override
        { 
            // �������������� ��������� ��������������
			return gcnew array<Type^> { Auth::PasswordCredentials::typeid }; 
        } 
		// �������� ������ ��������������
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override
		{
			// ��������� ��� ��������������
			if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
			{
				// ������� �������� ��������������
				return gcnew PasswordService(this, Handle); 
			}
			return nullptr; 
		}
		// ���������� ��� ���������
		public: virtual String^ GetUniqueID() override; 

		// ���������� ��� ���������� ��� ����������
		public: virtual String^ GetNativeContainerName(String^ name) override
		{ 
			// ���������� ��� ���������� ��� ����������
			return String::Format("\\\\.\\{0}\\{1}", Name, name); 
		}
		// ������������ �����������
		public: virtual array<String^>^ EnumerateObjects() override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// �����-����� ��� ���������� ��������
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStores : SecurityStore
	{
		// �����������
		public: SCardStores(CSP::Provider^ provider, CAPI::Scope scope, DWORD mode)

			// ��������� ���������� ���������
			: SecurityStore(provider, scope) { this->mode = mode; } private: DWORD mode;

        // ����������������� ���������
        public: property CSP::Provider^ Provider 
		{ 
			// ����������������� ���������
			CSP::Provider^ get() new { return (CSP::Provider^)SecurityStore::Provider; } 
		} 
		// ��� ���������
		public: virtual property Object^ Name { Object^ get() override { return "Card"; }}

		// ������ ���������� ����������
		protected: property DWORD Mode { DWORD get() { return mode; }}

		// ������������ �����������
		public: virtual array<String^>^ EnumerateObjects() override; 
		// ������� ��������� 
		public: virtual SecurityObject^ OpenObject(Object^ name, FileAccess access) override
		{
			// ������� �����-�����
			return SCardStore::Create(this, name->ToString(), mode); 
		}
	};
}}}
