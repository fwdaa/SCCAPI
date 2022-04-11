#pragma once
#include "Handle.h"
#include "Key.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	ref class Container; 

	///////////////////////////////////////////////////////////////////////////
	// ����������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CryptoProvider
	{
		private: Using<ProviderHandle^> handle;    // ��������� ����������
		private: Using<ProviderHandle^> handleGUI; // ��������� ����������
        private: DWORD		            type;      // ��� ����������

		// ������� ����������� ������ 
		private: Dictionary<String^, SecretKeyFactory^>^ secretKeyFactories; 
		private: Dictionary<String^,       KeyFactory^>^       keyFactories; 

		// �����������
		protected: Provider(DWORD type, String^ szName, bool sspi); 
		// ����������
		public: virtual ~Provider();  

		// ��� ����������
		public: virtual property DWORD Type { DWORD get() { return type; }}
        // ��� ����������
        public:	virtual property String^ Name { String^ get() override { return handle.Get()->Name; }}

		// ��������� ����������
		public: property ProviderHandle^ Handle { ProviderHandle^ get() { return handle.Get(); }}

        // ����� ������ ����������
        public: property DWORD Version { DWORD get() { return handle.Get()->GetLong(PP_VERSION, 0); }}

		// �������������� ������� ����������� ������
		public: virtual Dictionary<String^, SecretKeyFactory^>^ SecretKeyFactories() override { return secretKeyFactories; }
		public: virtual Dictionary<String^,       KeyFactory^>^       KeyFactories() override { return       keyFactories; }

		///////////////////////////////////////////////////////////////////////
		// ��������� ��������� ������
		///////////////////////////////////////////////////////////////////////

		// �������� ������� ����������� ��������� ������
		public:	virtual IRandFactory^ CreateRandFactory(SecurityObject^ scope, bool strong) override; 
		// �������� ��������� ��������� ������
		public:	virtual IRand^ CreateRand(Object^ window) override; 

		///////////////////////////////////////////////////////////////////////
		// ���������� �������� � ������������ ������
		///////////////////////////////////////////////////////////////////////

		// �������� ��� �����
		public: virtual SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) = 0; 

	    // ������������� ����
		public protected: virtual KeyHandle^ ImportKey(
			Container^ container, KeyHandle^ hPrivateKey, 
			IntPtr pBlob, DWORD cbBlob, DWORD flags
		); 
		///////////////////////////////////////////////////////////////////////
		// ���������� �������� � ��������/������ ������ ����������
		///////////////////////////////////////////////////////////////////////

		// ������������� ������������� �����
		public: virtual String^ ConvertKeyOID(ALG_ID algID) = 0; 

		// ������������� ������������� �����
		public: virtual ALG_ID ConvertKeyOID(String^ keyOID, DWORD keyType) = 0; 

		// ������������� ���� ������
		public protected: virtual KeyHandle^ ImportKeyPair(
			Container^ container, DWORD keyType, DWORD keyFlags, 
			IPublicKey^ publicKey, IPrivateKey^ privateKey
		); 
		// ������������� �������� ����
		public protected: virtual KeyHandle^ ImportPublicKey(
			ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType
        );
 		// �������������� �������� ����
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
			ExportPublicKey(KeyHandle^ hPublicKey);

		// �������� ������ ����
		public protected: virtual PrivateKey^ GetPrivateKey(SecurityObject^ scope, 
            IPublicKey^ publicKey, KeyHandle^ hKeyPair, DWORD keyType
		); 
	};
}}}