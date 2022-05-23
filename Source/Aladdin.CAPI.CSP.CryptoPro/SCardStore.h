#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ���������� ������������ �� �����-�����
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : CAPI::CSP::ProviderStore
	{
        // ��������� �����-����� � ������ �� �����-�����
		private: Using<CAPI::CSP::StoreHandle^> handle; BOOL destroy; SecurityObject^ applet; 

		// �����������
		public: static SCardStore^ Create(SecurityStore^ store, String^ name) 
		{
			// ������� ������ �����-�����
			SCardStore^ cardStore = gcnew SCardStore(store, name); 

			// ������� ������
			try { return (SCardStore^)Proxy::SecurityObjectProxy::Create(cardStore); }

			// ���������� ��������� ������
			catch (Exception^) { delete cardStore; throw; }
		}
		// �����������
		protected: SCardStore(SecurityStore^ store, String^ name); 
		// ����������
		public: virtual ~SCardStore();  

		// ��������� �����-�����
		public: property CAPI::CSP::StoreHandle^ Handle 
		{ 
			// ��������� �����-�����
			CAPI::CSP::StoreHandle^ get() { return handle.Get(); }
		}
		// ������� ������� ��������������
		public: virtual property bool HasAuthentication { bool get() override { return true; }}

        // ��������� ���� ��������������
        public: virtual array<Type^>^ GetAuthenticationTypes(String^ user) override; 
		// �������� ������ ��������������
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override; 

		// ��������� ��������������
		public: virtual array<Credentials^>^ Authenticate() override; 

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

		// ������ ��� ����������
		public: virtual String^ GetNativeContainerName(String^ name) override
		{
			// ������������ ������ ��� ����������
			return String::Format("\\\\.\\{0}\\{1}", Name, name); 
		}
		// ������������ �����������
		public: virtual array<String^>^ EnumerateObjects() override; 

		// ������� ���������
		public: virtual CAPI::SecurityObject^ CreateObject(IRand^ rand, 
			Object^ name, Object^ authenticationData, ...array<Object^>^ parameters) override; 
		// ������� ���������
		public: virtual void DeleteObject(Object^ name, 
			array<CAPI::Authentication^>^ authentications) override; 

		// ���������� ������� ������������� �� ���������
		public: virtual void SetDefaultContainer(CAPI::CSP::Container^ container)
		{
			// ���������� ������� ������������� �� ���������
			container->Handle->SetLong(PP_CONTAINER_DEFAULT, 0, 0);
		} 
	};
}}}}
