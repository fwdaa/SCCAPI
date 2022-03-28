#pragma once
#include "RegistryStore.h"
#include "SCardStores.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CSP::Provider
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian;
		   
		// �����������
		public: Provider(DWORD type) : CAPI::CSP::Provider(type, nullptr, false)
		
			// ��������� ������ ����������
			{ version = Version; } private: DWORD version;

        // ����� ������ ����������
        public: property String^ Timestamp { String^ get()
        {
            // �������� ����� ������ ����������
            return Handle->GetString(PP_VERSION_TIMESTAMP, 0);
        }}
		// ��� ������ �����������
		public: virtual property String^ Group { String^ get() override 
		{ 
			// ��� ������ �����������
			return CP_GR3410_2001_PROV_W; 
		}}
		// �������� ��������� ����������
		public: virtual array<String^>^ EnumerateStores(Scope scope) override 
		{ 
			// ������� ����� �������� �����������
			if (scope == Scope::System) return gcnew array<String^> { "HKLM", "Card" }; 
			if (scope == Scope::User  ) return gcnew array<String^> { "HKCU", "Card" }; 

			return gcnew array<String^>(0); 
		}
		// ����������� ��� ����������
		public: virtual array<SecurityInfo^>^ EnumerateAllObjects(Scope scope) override; 

		// �������� ��������� �����������
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ storeName) override 
		{ 
			if (scope == Scope::System) 
			{
				// ������� ��������� �����������
				if (storeName == "HKLM") return RegistryStore::Create(this, scope); 
				if (storeName == "Card") return gcnew SCardStores    (this, scope); 
			}
			if (scope == Scope::User) 
			{
				// ������� ��������� �����������
				if (storeName == "HKCU") return RegistryStore::Create(this, scope); 
				if (storeName == "Card") return gcnew SCardStores    (this, scope); 
			}
			// ��� ������ ��������� ����������
			throw gcnew NotFoundException(); 
		}
		// ������� �������� ���������� ���� 28147-89
		public: CAPI::CSP::BlockCipher^ CreateGOST28147(String^ paramOID); 

	    // �������������� ������� ����������� ������
		public: virtual array<KeyFactory^>^ KeyFactories() override; 

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			CAPI::Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;

		// �������� ��� �����
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override; 

		///////////////////////////////////////////////////////////////////////
		// ���������� �������� � ��������/������ ������ ����������
		///////////////////////////////////////////////////////////////////////

        // ������������� ��������� ���������� �����
        public protected: String^ GetExportKeyOID(String^ keyOID, DWORD keyType); 

        // ������������� ��������� ���������� �����
        public protected: ALG_ID GetExportID(String^ keyOID)
        {
            // ������� ������������� ��������� ���������� ����� 
            return (keyOID == ASN1::GOST::OID::gostR3410_2001) ? CALG_PRO_EXPORT : CALG_PRO12_EXPORT; 
        } 
	    // ������� �������� ���������� �����
		public protected: KeyWrap^ CreateExportKeyWrap(
			CAPI::CSP::ContextHandle^ hContext, 
			ALG_ID exportID, String^ sboxOID, array<BYTE>^ ukm
		);
		// ������������� ������������� �����
		public: virtual String^ ConvertKeyOID(ALG_ID keyOID) override; 

		// ������������� ������������� �����
		public: virtual ALG_ID ConvertKeyOID(String^ keyOID, DWORD keyType) override; 

		// ������������� ���� ������
		public protected: virtual Aladdin::CAPI::CSP::KeyHandle^ ImportKeyPair(
			CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
			IPublicKey^ publicKey, IPrivateKey^ privateKey) override; 

		// ������������� �������� ����
		public protected: virtual CAPI::CSP::KeyHandle^ ImportPublicKey(
			CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType) override; 

		// ������������� ������ ��������� �����
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ ExportPublicKey(
			CAPI::CSP::KeyHandle^ hPublicKey) override;
		
		// �������� ������ ����
		public protected: virtual CAPI::CSP::PrivateKey^ GetPrivateKey(SecurityObject^ scope, 
			IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType
		) override;
	}; 
}}}}}
