#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Microsoft Primitive Provider
	///////////////////////////////////////////////////////////////////////////
	public ref class PrimitiveProvider : CAPI::Factory, IRandFactory
	{
		// ��� ����������
		public: property String^ Provider { String^ get() { return "Microsoft Primitive Provider"; }}

		// �������������� ������� ����������� ������
		public: virtual array<SecretKeyFactory^>^ SecretKeyFactories() override
		{
			// �������������� ������� ����������� ������
			return gcnew array<SecretKeyFactory^> { 
				ANSI::Keys::RC2 ::Instance, ANSI::Keys::RC4 ::Instance, 
				ANSI::Keys::DES ::Instance, ANSI::Keys::DESX::Instance, 
				ANSI::Keys::TDES::Instance, ANSI::Keys::AES ::Instance
			}; 
		}
		// �������������� ������� ����������� ������
		public: virtual array<KeyFactory^>^ KeyFactories() override
		{
			// �������������� ������� ����������� ������
			return gcnew array<KeyFactory^> { 
				gcnew ANSI::RSA ::KeyFactory(ASN1::ISO::PKCS::PKCS1::OID::rsa   ), 
				gcnew ANSI::X942::KeyFactory(ASN1::ANSI::OID::x942_dh_public_key), 
				gcnew ANSI::X957::KeyFactory(ASN1::ANSI::OID::x957_dsa          ), 
				gcnew ANSI::X962::KeyFactory(ASN1::ANSI::OID::x962_ec_public_key) 
			}; 
		}
		// �������� ��������� �� ���������
		public: virtual CAPI::Culture^ GetCulture(SecurityStore^ scope, String^ keyOID) override
        {
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// �������� ��������� �� ���������
			return factory.Get()->GetCulture(scope, keyOID); 
		}
		// �������� ��������� �� ���������
		public: virtual PBE::PBECulture^ GetCulture(PBE::PBEParameters^ parameters, String^ keyOID) override
        {
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// �������� ��������� �� ���������
			return factory.Get()->GetCulture(parameters, keyOID); 
		}
		// ������� ��������� ��������� ������
		public: virtual IRand^ CreateRand(Object^ window) 
		{
			// ������� ��������� ��������� ������
			return gcnew CAPI::CNG::Rand(Provider, BCRYPT_RNG_ALGORITHM, 0, window); 
		} 
		// ���������� ��� ���������
		public: static PCWSTR GetHashName(String^ hashOID)
		{
			// ���������� ������������� ��������� �����������
			if (hashOID == Aladdin::ASN1::ANSI::OID::rsa_md2	  ) return BCRYPT_MD2_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::rsa_md4	  ) return BCRYPT_MD4_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::rsa_md5	  ) return BCRYPT_MD5_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::ssig_sha1    ) return BCRYPT_SHA1_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::nist_sha2_256) return BCRYPT_SHA256_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::nist_sha2_384) return BCRYPT_SHA384_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::nist_sha2_512) return BCRYPT_SHA512_ALGORITHM;

			// ��� ������ ��������� ����������
			throw gcnew NotSupportedException();
		}
		// ������� �������� ��������� ������
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ factory, SecurityObject^ scope, 
			String^ keyOID, IParameters^ parameters, IRand^ rand) override; 

		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			CAPI::Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type) override;
	};
}}}}}
