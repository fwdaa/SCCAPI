#pragma once
#include "..\Provider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� RSA
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : Microsoft::Provider
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// �����������
		public: Provider(DWORD type, String^ name, bool sspi, bool oaep) 

			// ��������� ���������� ���������
			: Microsoft::Provider(type, name, sspi) { this->oaep = oaep; } private: bool oaep; 

		// ������� ��� �����
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override;

		// �������������� ������� ����������� ������
		public: virtual array<KeyFactory^>^ KeyFactories() override
		{
			// �������������� ������� ����������� ������
			return gcnew array<KeyFactory^> { gcnew ANSI::RSA::KeyFactory(ASN1::ISO::PKCS::PKCS1::OID::rsa) }; 
		}
		// ������� �������� ��������� ������
		public protected: virtual CAPI::KeyPairGenerator^ CreateGenerator(
			Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;

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

		// �������� ������������� �����
		public: virtual String^ ConvertKeyOID(ALG_ID algID) override
		{
			switch (algID)
			{
			// ������� ������������� �����
			case CALG_RSA_KEYX: return ASN1::ISO::PKCS::PKCS1::OID::rsa; 
			case CALG_RSA_SIGN: return ASN1::ISO::PKCS::PKCS1::OID::rsa; 
			}
			// ���������������� ����
			throw gcnew NotSupportedException(); 
		}
		// ������������� ������������� �����
		public: virtual ALG_ID ConvertKeyOID(String^ keyOID, DWORD keyType) override
		{
			if (keyOID == ASN1::ISO::PKCS::PKCS1::OID::rsa)
			{
				// ������� ������������� �����
				return (keyType == AT_KEYEXCHANGE) ? CALG_RSA_KEYX : CALG_RSA_SIGN; 
			}
			// ���������������� ����
			throw gcnew NotSupportedException(); 
		}
	}; 
}}}}}}
