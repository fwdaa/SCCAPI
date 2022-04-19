#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Microsoft Primitive Provider
	///////////////////////////////////////////////////////////////////////////
	public ref class PrimitiveProvider : CAPI::Factory, IRandFactory
	{
		// фабрики кодирования ключей 
		private: Dictionary<String^, KeyFactory^>^ keyFactories; 

		// конструктор
		public: PrimitiveProvider() { keyFactories = gcnew Dictionary<String^, KeyFactory^>(); 

			// заполнить список фабрик кодирования ключей
			KeyFactories()->Add(ASN1::ISO::PKCS::PKCS1::OID::rsa, 
				gcnew ANSI::RSA::KeyFactory(ASN1::ISO::PKCS::PKCS1::OID::rsa)
			); 
			KeyFactories()->Add(ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep, 
				gcnew ANSI::RSA::KeyFactory(ASN1::ISO::PKCS::PKCS1::OID::rsa_oaep)
			); 
			KeyFactories()->Add(ASN1::ISO::PKCS::PKCS1::OID::rsa_pss, 
				gcnew ANSI::RSA::KeyFactory(ASN1::ISO::PKCS::PKCS1::OID::rsa_pss)
			); 
			KeyFactories()->Add(ASN1::ANSI::OID::x942_dh_public_key, 
				gcnew ANSI::X942::KeyFactory(ASN1::ANSI::OID::x942_dh_public_key) 
			); 
			KeyFactories()->Add(ASN1::ANSI::OID::x957_dsa, 
				gcnew ANSI::X957::KeyFactory(ASN1::ANSI::OID::x957_dsa)
			); 
			KeyFactories()->Add(ASN1::ANSI::OID::x962_ec_public_key, 
				gcnew ANSI::X962::KeyFactory(ASN1::ANSI::OID::x962_ec_public_key)
			); 
		} 
		// имя провайдера
		public: property String^ Provider { String^ get() { return "Microsoft Primitive Provider"; }}

		// поддерживаемые фабрики кодирования ключей
		public: virtual Dictionary<String^, KeyFactory^>^ KeyFactories() override { return keyFactories; }

		// создать генератор случайных данных
		public: virtual IRand^ CreateRand(Object^ window) 
		{
			// создать генератор случайных данных
			return gcnew CAPI::CNG::Rand(Provider, BCRYPT_RNG_ALGORITHM, 0, window); 
		} 
		// определить имя алгоритма
		public: static PCWSTR GetHashName(String^ hashOID)
		{
			// определить идентификатор алгоритма хэширования
			if (hashOID == Aladdin::ASN1::ANSI::OID::rsa_md2	  ) return BCRYPT_MD2_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::rsa_md4	  ) return BCRYPT_MD4_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::rsa_md5	  ) return BCRYPT_MD5_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::ssig_sha1    ) return BCRYPT_SHA1_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::nist_sha2_256) return BCRYPT_SHA256_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::nist_sha2_384) return BCRYPT_SHA384_ALGORITHM;
			if (hashOID == Aladdin::ASN1::ANSI::OID::nist_sha2_512) return BCRYPT_SHA512_ALGORITHM;

			// при ошибке выбросить исключение
			throw gcnew NotSupportedException();
		}
		// создать алгоритм генерации ключей
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ factory, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			CAPI::Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, Type^ type) override;
	};
}}}}}
