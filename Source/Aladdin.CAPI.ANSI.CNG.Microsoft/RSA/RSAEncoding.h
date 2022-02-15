#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Кодирование ключей
	///////////////////////////////////////////////////////////////////////////
	ref class Encoding abstract sealed 
	{
		// способ кодирования чисел
		public: static const Math::Endian Endian = Math::Endian::BigEndian; 

		// преобразовать формат открытого ключа
		public: static ASN1::ISO::PKIX::SubjectPublicKeyInfo^ GetPublicKeyInfo(
			CAPI::CNG::NKeyHandle^ hPublicKey
		);
		// получить структуру для импорта личного ключа
		public: static DWORD GetPrivateKeyBlob(ANSI::RSA::IPrivateKey^ privateKey, 
			BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob
		); 
		// получить структуру для импорта открытого ключа
		public: static DWORD GetPublicKeyBlob(ANSI::RSA::IPublicKey^ publicKey, 
			BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob
		); 
	}; 
}}}}}}
