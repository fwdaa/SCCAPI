#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace X962
{
	///////////////////////////////////////////////////////////////////////////
	// Кодирование ключей
	///////////////////////////////////////////////////////////////////////////
	ref class Encoding abstract sealed 
	{
		// способ кодирования чисел
		public: static const Math::Endian Endian = Math::Endian::BigEndian; 

		// определить имя алгоритма
		public: static String^ GetKeyName(ANSI::X962::IParameters^ parameters, DWORD keyType);

		// преобразовать формат открытого ключа
		public: static ASN1::ISO::PKIX::SubjectPublicKeyInfo^ GetPublicKeyInfo(
			CAPI::CNG::NKeyHandle^ hPublicKey
		);
		// получить структуру для импорта открытого и личного ключа
		public: static DWORD GetKeyPairBlob(String^ algName, ANSI::X962::IPublicKey^ publicKey, 
			ANSI::X962::IPrivateKey^ privateKey, BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob
		); 
		// получить структуру для импорта личного ключа
		public: static DWORD GetPrivateKeyBlob(String^ algName, ANSI::X962::IPrivateKey^ privateKey, 
			BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob
		); 
		// получить структуру для импорта открытого ключа
		public: static DWORD GetPublicKeyBlob(String^ algName, ANSI::X962::IPublicKey^ publicKey, 
			BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob
		); 
		// закодировать подпись
		public: static array<BYTE>^ EncodeSignature(
			ANSI::X962::IParameters^ parameters, ASN1::ANSI::X962::ECDSASigValue^ signature
		); 
		// раскодировать подпись
		public: static ASN1::ANSI::X962::ECDSASigValue^ DecodeSignature(
			ANSI::X962::IParameters^ parameters, array<BYTE>^ encoded
		); 
	}; 
}}}}}}
