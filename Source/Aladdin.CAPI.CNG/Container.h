#pragma once
#include "Handle.h"
#include "Store.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////////
	// ����������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class Container : CAPI::Container
	{
		// ������ ������ ���������� � ����� �������� 
		private: Using<NKeyHandle^> hKeyPair; private: DWORD keyType; private: DWORD mode; 

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
		protected: Container(ProviderStore^ store, String^ name, DWORD mode); 
		// ����������
		public: virtual ~Container();  

        // ����������������� ���������
        public: property NProvider^ Provider 
		{ 
			// ����������������� ���������
			NProvider^ get() new { return Store->Provider; } 
		} 
        // ��������� ����������
        public: property ProviderStore^ Store 
        {
            // ��������� ����������
            ProviderStore^ get() new { return (ProviderStore^)CAPI::Container::Store; }
        }
		// ����� �������� ����������
        protected: property DWORD Mode { DWORD get() { return mode; }}

		// ��������� �����
		public: property NKeyHandle^ Handle { NKeyHandle^ get() { return hKeyPair.Get(); }}
		// ��� �����
		public: property DWORD KeyType { DWORD get() { return keyType; }}

		///////////////////////////////////////////////////////////////////////
		// ���������� ���������������
		///////////////////////////////////////////////////////////////////////

		// ��������� ������������� ��������������
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
				return gcnew PasswordService(this, nullptr); 
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
		///////////////////////////////////////////////////////////////////////
		// ����� ��������
		///////////////////////////////////////////////////////////////////////

		// �������� ������������� ��� ������ �����
		public protected: array<BYTE>^ GetKeyID(KeyUsage keyUsage); 

		// ����������� �������������� ������
		public: virtual array<array<BYTE>^>^ GetKeyIDs() override; 

		// �������� ������������� �� �������� �����
		public: virtual array<array<BYTE>^>^ GetKeyIDs(ASN1::ISO::PKIX::SubjectPublicKeyInfo^ keyInfo) override; 

		// ������� �������� ����
		public: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ GetPublicKeyInfo(array<BYTE>^ keyID); 

		// ������� �������� ����
		public: virtual IPublicKey^ GetPublicKey(array<BYTE>^ keyID) override; 

		// ������� ������ ����
		public: virtual IPrivateKey^ GetPrivateKey(array<BYTE>^ keyID) override; 

		///////////////////////////////////////////////////////////////////////
		// ���������� �������������
		///////////////////////////////////////////////////////////////////////

		// �������� ���������� ��������� �����
		public: virtual Certificate^ GetCertificate(array<BYTE>^ keyID) override; 

		// ��������� ���������� ��������� �����
		public: virtual void SetCertificate(
			array<BYTE>^ keyID, Certificate^ certificate) override; 

		// ��������� ���� ������
		public: virtual array<BYTE>^ SetKeyPair(IRand^ rand, 
			KeyPair^ keyPair, KeyUsage keyUsage, KeyFlags keyFlags) override;

		// ������� ���� ������
		public: virtual void DeleteKeyPair(array<BYTE>^ keyID) override;

		// ������� ����� ����������
		public: virtual void DeleteKeys() override;

		///////////////////////////////////////////////////////////////////////
		// ���������� �������� � ������ ������ ����������
		///////////////////////////////////////////////////////////////////////

		// ���������� ��������� �������� ����
		private: void CompleteGenerateKeyPair(IntPtr hwnd, 
			BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags
        );
		// ������������� ���� ������
		public protected: NKeyHandle^ GenerateKeyPair(IntPtr hwnd, 
			String^ alg, DWORD keyType, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags
        );
		// ������������� ����
		public protected: NKeyHandle^ ImportKeyPair(IntPtr hwnd,
			NKeyHandle^ hKey, DWORD keyType, String^ typeBlob, IntPtr ptrBlob, 
			DWORD cbBlob, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags
		);
		// �������������� ����
		public protected: array<BYTE>^ ExportKey(
			NKeyHandle^ hKey, NKeyHandle^ hExportKey, String^ blobType, DWORD flags
        );
		// ��������� ������������ ������ �����
		public protected: NSecretHandle^ AgreementSecret(
			NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey, DWORD flags
		);
		// ������������ ������
		public protected: array<BYTE>^ Decrypt(
			NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ data, DWORD flags
        );
		// ��������� ���-��������
		public protected: array<BYTE>^ SignHash(
			NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ hash, DWORD flags
        ); 
	};
}}}