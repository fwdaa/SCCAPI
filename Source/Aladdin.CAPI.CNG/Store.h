#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ��������� ��������������
	///////////////////////////////////////////////////////////////////////////
	public ref class PasswordService : Auth::PasswordService
	{
		// �����������
		public: PasswordService(SecurityObject^ obj, NKeyHandle^ handle) 
			
			// ��������� ���������� ���������
			: Auth::PasswordService(obj, "USER") 
        
			// ��������� ���������� ���������
			{ this->handle = handle; } private: NKeyHandle^ handle;

		// ���������� ������������������ ������
		protected: virtual void SetPassword(String^ password) override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ���������� �������� 
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderStore : ContainerStore
	{
		// ��� ��������� � ����� ��������
		private: String^ name; private: DWORD mode; 

		// �����������
		public: ProviderStore(NProvider^ provider, CAPI::Scope scope, String^ name, DWORD mode)

			// ��������� ���������� ���������
			: ContainerStore(provider, scope) { this->name = name; this->mode = mode; } 

		// �����������
		public: ProviderStore(SecurityStore^ store, String^ name, DWORD mode) 
			
			// ��������� ���������� ���������
			: ContainerStore(store) { this->name = name; this->mode = mode; }

        // ����������������� ���������
        public: property NProvider^ Provider 
		{ 
			// ����������������� ���������
			NProvider^ get() new { return (NProvider^)ContainerStore::Provider; } 
		} 
		// ��� ���������
		public: virtual property Object^ Name { Object^ get() override { return name; }}

		// ������ ���������� ����������
		protected: property DWORD Mode { DWORD get() { return mode; }}

		// ������� ������� ��������������
		public: virtual property bool HasAuthentication { bool get() { return false; }}
		// ��������� ������������� ��������������
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
		public: virtual void DeleteObject(Object^ name, 
			array<CAPI::Authentication^>^ authentications) override; 

		// �������� ���������� ��������� �����
		public protected: virtual Certificate^ GetCertificate(NKeyHandle^ hPrivateKey, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo
		);
		// �������� ���� ������������
		public protected: virtual array<Certificate^>^ GetCertificateChain(Certificate^ certificate); 

		// ��������� ���������� ��������� �����
		public protected: virtual void SetCertificateChain(
			NKeyHandle^ hPrivateKey, array<Certificate^>^ certificateChain
		); 
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������� ����������� � �������
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CAPI::CNG::ProviderStore
	{
		// �����������
		public: RegistryStore(NProvider^ provider, CAPI::Scope scope, DWORD mode); 
			
		// ����������� ����������
		public: virtual array<String^>^ EnumerateObjects() override; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// �����-����� ��� ���������� ��������
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : ProviderStore
	{
		// ��������� �����-�����
		private: NKeyHandle^ hCard; 

		// �����������
		public: static SCardStore^ Create(SecurityStore^ store, String^ name, DWORD mode) 
		{
			// ������� ������ �����-�����
			SCardStore^ cardStore = gcnew SCardStore(store, name, mode); 

			// ������� ������
			try { return (SCardStore^)Proxy::SecurityObjectProxy::Create(cardStore); }

			// ���������� ��������� ������
			catch (Exception^) { delete cardStore; throw; }
		}
		// �����������
		protected: SCardStore(SecurityStore^ store, String^ name, DWORD mode);   
		// ����������
		public: virtual ~SCardStore() { Handle::Release(hCard); }

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
				return gcnew PasswordService(this, hCard); 
			}
			return nullptr; 
		}
		// ������� ������
		public: property String^ Password { void set(String^ value)
		{ 
            // ������� ��������� ��������������
            CAPI::Authentication^ authentication = 
				gcnew Auth::PasswordCredentials("USER", value); 

            // ���������� � ��������� ��������������
            Authentication = authentication; Authenticate(); 
		}}
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
		public: SCardStores(NProvider^ provider, CAPI::Scope scope, DWORD mode)

			// ��������� ���������� ���������
			: SecurityStore(provider, scope) { this->mode = mode; } private: DWORD mode;

        // ����������������� ���������
        public: property NProvider^ Provider 
		{ 
			// ����������������� ���������
			NProvider^ get() new { return (NProvider^)SecurityStore::Provider; } 
		} 
		// ��� ���������
		public: virtual property Object^ Name { Object^ get() override { return "Card"; }}

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
