#pragma once
#include "..\Provider.h"
#include "..\RegistryStore.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace DSS 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� DSS
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : Microsoft::Provider
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// �����������
		public: Provider(DWORD type, String^ name, bool sspi) : Microsoft::Provider(type, name, sspi) 
		{
			// ��������� ������ ������ ����������� ������
			KeyFactories()->Add(ASN1::ANSI::OID::x942_dh_public_key, 
				gcnew ANSI::X942::KeyFactory(ASN1::ANSI::OID::x942_dh_public_key) 
			); 
			KeyFactories()->Add(ASN1::ANSI::OID::x957_dsa, 
				gcnew ANSI::X957::KeyFactory(ASN1::ANSI::OID::x957_dsa)
			); 
		}
		// ������� ��� �����
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override;

		// ����������� ��������� �����������
		public: virtual array<String^>^ EnumerateStores(Scope scope) override
		{
			// ������� ����� ��������
			if (scope == Scope::System) return gcnew array<String^> { "HKLM" }; 
			if (scope == Scope::User  ) return gcnew array<String^> { "HKCU" }; 

			return gcnew array<String^>(0); 
		}
		// �������� ��������� ����������
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override
		{
			// ��������� ���������� �����
			if (scope == Scope::System && name != "HKLM")
			{
				// ��� ������ ��������� ����������
				throw gcnew NotFoundException(); 
			}
			// ��������� ���������� �����
			if (scope == Scope::User && name != "HKCU")
			{
				// ��� ������ ��������� ����������
				throw gcnew NotFoundException(); 
			}
			// ������� ��������� �����������
			return gcnew RegistryStore(this, scope);
		}
		// ������� �������� ��������� ������
		public protected: virtual CAPI::KeyPairGenerator^ CreateGenerator(
			Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;

		// ������������� ���� ������
		public protected: virtual CAPI::CSP::KeyHandle^ ImportKeyPair(
			CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
			IPublicKey^ publicKey, IPrivateKey^ privateKey) override;

		// ������������� �������� ����
		public protected: virtual CAPI::CSP::KeyHandle^ ImportPublicKey(
			CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType) override; 

		// �������������� �������� ����
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ ExportPublicKey(
			CAPI::CSP::KeyHandle^ hPublicKey) override;
	
		// �������� ������ ����
		public protected: virtual CAPI::CSP::PrivateKey^ GetPrivateKey(SecurityObject^ scope, 
			IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType
		) override;

		// ������������� ������������� �����
		public: virtual String^ ConvertKeyOID(ALG_ID algID) override
		{
			switch (algID)
			{
			// ������� ������������� �����
			case CALG_DSS_SIGN	: return ASN1::ANSI::OID::x957_dsa;
			case CALG_DH_SF		: return ASN1::ANSI::OID::x942_dh_public_key;
			case CALG_DH_EPHEM	: return ASN1::ANSI::OID::x942_dh_public_key;
			}
			// ���������������� ����
			throw gcnew NotSupportedException(); 
		}
		// ������������� ������������� �����
		public: virtual ALG_ID ConvertKeyOID(String^ keyOID, DWORD keyType) override
		{
			if (keyOID == ASN1::ANSI::OID::x942_dh_public_key)
			{
				// ������� ������������� �����
				if (keyType == AT_KEYEXCHANGE) return CALG_DH_SF; 
			}
			if (keyOID == ASN1::ANSI::OID::x957_dsa)
			{
				// ������� ������������� �����
				if (keyType == AT_SIGNATURE) return CALG_DSS_SIGN; 
			}
			// ���������������� ����
			throw gcnew NotSupportedException(); 
		}
	};
}}}}}
