#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar 
{
	///////////////////////////////////////////////////////////////////////////
	// ����������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class Container : CAPI::CSP::Container
	{
		// ������ ��� ����������
		private: String^ nativeName; 

        // �����������
		public: static Container^ Create(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
		{
			// ������� ������ ����������
			Container^ container = gcnew Container(store, name, mode); 

			// ������� ������
			try { return (Container^)Proxy::SecurityObjectProxy::Create(container); }

			// ���������� ��������� ������
			catch (Exception^) { delete container; throw; } 
		}
		// �����������
		protected: Container(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
			
			// ��������� ���������� ���������
			: CAPI::CSP::Container(store, name, mode) 
		{
			// ������� ������ ��� ����������
			nativeName = store->GetNativeContainerName(name); 
		} 
		// ���������� ��� ���������
		public: virtual String^ GetUniqueID() override; 

		///////////////////////////////////////////////////////////////////////////
		// ��������� ��������� ����� ��� ����������
		///////////////////////////////////////////////////////////////////////////
		public protected: ref class SetActivePrivateKey 
		{
			// ��������� ���������� � ������������� ��������� �����
			private: CAPI::CSP::ContainerHandle^ hContainer; array<BYTE>^ keyID; 

			// �����������
			public: SetActivePrivateKey(Container^ container, CAPI::CSP::PrivateKey^ privateKey); 
			// ����������
			public: virtual ~SetActivePrivateKey(); 
		};
		/////////////////////////////////////////////////////////////////////////////
		// ��������� ��������������
		/////////////////////////////////////////////////////////////////////////////
		private: ref class PasswordService : Auth::PasswordService
		{
			// �����������
			public: PasswordService(Container^ store) : Auth::PasswordService(store, "USER") {}
        
			// ���������� ������������������ ������
			protected: virtual void SetPassword(String^ password) override
			{
				// ���������� ������ ����������
				((Container^)Target)->SetPassword(password);
			}
		}; 
		// ��������� ������� ���������� ��������������
		public: virtual bool IsAuthenticationRequired(Exception^ e) override; 

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
				return gcnew PasswordService(this); 
			}				
			return nullptr; 
		}
		// ���������� ������ ����������
		private: void SetPassword(String^ password); 

		///////////////////////////////////////////////////////////////////////
		// ���������� �������
		///////////////////////////////////////////////////////////////////////

		// �������� ��������� �������� ����
		public protected: virtual CAPI::CSP::KeyHandle^ GetUserKey(
			array<BYTE>^ keyID, DWORD% keyType) override; 

		// �������� ��� ��� ������ �����
		public protected: virtual DWORD GetKeyType(
			String^ keyOID, KeyUsage keyUsage) override; 

		// ����������� �������������� ������
		public: virtual array<array<BYTE>^>^ GetKeyIDs() override; 

		// ������� ���� ������
		public: virtual void DeleteKeyPair(array<BYTE>^ keyID) override; 
		// ������� ��� �����
		public: virtual void DeleteKeys() override;

		///////////////////////////////////////////////////////////////////////
		// ���������� �������� � ������ ������ ����������
		///////////////////////////////////////////////////////////////////////

		// ������������� ����
		public protected: CAPI::CSP::KeyHandle^ ImportKey(
			CAPI::CSP::KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags)
		{
			// ������������� ����
			return CAPI::CSP::Container::ImportKey(hImportKey, ptrBlob, cbBlob, flags); 
		}
		// �������������� ����
		public protected: array<BYTE>^ ExportKey(
			CAPI::CSP::KeyHandle^ hKey, CAPI::CSP::KeyHandle^ hExportKey, DWORD exportType, DWORD flags)
		{
			// �������������� ����
			return CAPI::CSP::Container::ExportKey(hKey, hExportKey, exportType, flags); 
		}
	}; 
}}}}
