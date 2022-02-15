#pragma once
#include "Handle.h"
#include "Store.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// ����������������� ���������. �������������� ��� ������������ 
	// ��������������:
	// 1) ���������� �������������� (������ - ���������� ������� Microsoft); 
	// 2) �������������� ���������� ���������� (������ - ���������� ������� 
	//    CryptoPro); 
	// 3) �������������� ����������������� ��������� ���������� 
	//    (������ - ���������� �� �����-�����). � ������ ������ �������������� 
	//    ���������� ����� ��������� ��������� (������ ����������� � ��������� 
	//    ����� CRYPT_DEFAULT_CONTAINER_OPTIONAL), � ����� �������������� 
	//    �������������� �� ��������� ����������. 
	///////////////////////////////////////////////////////////////////////////
	public ref class Container : CAPI::Container, IRandFactory
	{
        // ��������� ���������� � ����� ��������
		private: ContainerHandle^ handle; DWORD mode; 
	
        // �����������
		public: static Container^ Create(ProviderStore^ store, String^ name, DWORD mode) 
		{
			// ������� ������ ����������
			Container^ container = gcnew Container(store, name, mode); 

			// ������� ������
			try { return (Container^)Proxy::SecurityObjectProxy::Create(container); }

			// ���������� ��������� ������
			catch (Exception^) { delete container; throw; }
		}
		// �����������
		protected: Container(ProviderStore^ store, String^ name, DWORD mode) : CAPI::Container(store, name)
		{
			// ������� ��������� ����������
			handle = nullptr; AttachHandle(mode);  
		}
		// ����������
		public: virtual ~Container() { DetachHandle(); } 

        // ����������������� ���������
        public: property CSP::Provider^ Provider 
		{ 
			// ����������������� ���������
			CSP::Provider^ get() new { return Store->Provider; } 
		} 
        // ��������� ����������
        public: property ProviderStore^ Store 
        {
            // ��������� ����������
            ProviderStore^ get() new { return (ProviderStore^)CAPI::Container::Store; }
        }
        // ���������� ����������
        public: virtual property SecurityInfo^ Info 
        {
            // ��������� ����������
            SecurityInfo^ get() override sealed { return CAPI::Container::Info; }
        }
		// �������� ��������� ����������
		public: property ContainerHandle^ Handle 
		{ 
			// �������� ��������� ����������
			ContainerHandle^ get() { return handle; }
		}
		// ����� �������� ����������
        protected: property DWORD Mode { DWORD get() { return mode; }}

		// ������� ��������� ��������� ������
		public: virtual IRand^ CreateRand(Object^ window); 

		///////////////////////////////////////////////////////////////////////
		// �������� � ���������� ����������
		///////////////////////////////////////////////////////////////////////
		protected: void AttachHandle(String^ nativeName, DWORD mode); 
		protected: void AttachHandle(DWORD mode)
		{
			// ������� ��������� ����������
			AttachHandle(Store->GetNativeContainerName(Name->ToString()), mode); 
		}
		protected: void DetachHandle(); 

		///////////////////////////////////////////////////////////////////////
		// ���������� ���������������
		///////////////////////////////////////////////////////////////////////

		// ��������� ������� ���������� ��������������
		public: virtual bool IsAuthenticationRequired(Exception^ e) override; 

		// �������������� ���� ��������������
		public: virtual array<Type^>^ GetAuthenticationTypes(String^ user) override
        { 
			// ��������� ��� ������������
			if (Store->HasAuthentication) return gcnew array<Type^>(0); 

            // �������������� ��������� ��������������
			return gcnew array<Type^> { Auth::PasswordCredentials::typeid }; 
        } 
		// �������� ������ ��������������
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override
		{
			// ��������� ��� ������������
			if (Store->HasAuthentication) return nullptr; 

			// ��������� ��� ��������������
			if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
			{
				// ������� �������� ��������������
				return gcnew PasswordService(this, Handle); 
			}
			return nullptr; 
		}
		// ��������� ��������������
		public: virtual array<Credentials^>^ Authenticate() override; 

		///////////////////////////////////////////////////////////////////////
		// ����� ��������
		///////////////////////////////////////////////////////////////////////

		// �������� ��� ��� ������ �����
		public protected: virtual DWORD GetKeyType(String^ keyOID, KeyUsage keyUsage); 

		// ����������� �������������� ������
		public: virtual array<array<BYTE>^>^ GetKeyIDs() override; 

		// ������� �������� ����
		public: virtual IPublicKey^ GetPublicKey(array<BYTE>^ keyID) override; 

		// ������� ������ ����
		public: virtual IPrivateKey^ GetPrivateKey(array<BYTE>^ keyID) override; 

		///////////////////////////////////////////////////////////////////////
		// ���������� ������������� � �������
		///////////////////////////////////////////////////////////////////////

		// �������� ���������� ��������� �����
		public: virtual Certificate^ GetCertificate(array<BYTE>^ keyID) override; 

		// ��������� ���������� ��������� �����
		public: virtual void SetCertificate(
			array<BYTE>^ keyID, Certificate^ certificate) override; 

		// ������� ���������� � ������
		public: void SetCertificateContext(PCCERT_CONTEXT pCertificateContext);

		// ��������� ���� ������
		public: virtual array<BYTE>^ SetKeyPair(IRand^ rand, 
			KeyPair^ keyPair, KeyUsage keyUsage, KeyFlags keyFlags) override;

		// ������� ���� ������
		public: virtual void DeleteKeyPair(array<BYTE>^ keyID) override
		{
			// �������� �� ��������������
			throw gcnew NotSupportedException();
		}
		// ������� ��� �����
		public: virtual void DeleteKeys() override;

		///////////////////////////////////////////////////////////////////////
		// ���������� �������� � ������ ������ ����������
		///////////////////////////////////////////////////////////////////////

		// �������� ��������� �������� ����
		public protected: virtual KeyHandle^ GetUserKey(array<BYTE>^ keyID, DWORD% keyType)
		{
			// �������� ��������� �������� ����
			keyType = keyID[0]; return Handle->GetUserKey(keyType); 
		}
		// ������������� ����
		public protected: virtual KeyHandle^ GenerateKeyPair(
			IntPtr hwnd, ALG_ID algID, DWORD flags
		);
		// ������������� ����
		public protected: KeyHandle^ ImportKey(
			KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags
		);
		// �������������� ����
		public protected: array<BYTE>^ ExportKey(
			KeyHandle^ hKey, KeyHandle^ hExportKey, DWORD exportType, DWORD flags
		);
		// ������������ ������
		public protected: array<BYTE>^ Decrypt(
			KeyHandle^ hKey, array<BYTE>^ data, DWORD flags
		);
		// ��������� ���-��������
		public protected: array<BYTE>^ SignHash(
			DWORD keyType, HashHandle^ hHash, DWORD flags
		); 
	};
}}}