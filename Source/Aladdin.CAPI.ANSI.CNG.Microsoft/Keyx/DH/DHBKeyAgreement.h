#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace DH
{
	//////////////////////////////////////////////////////////////////////////////
	// Алгоритм согласования общего ключа
	//////////////////////////////////////////////////////////////////////////////
	public ref class BKeyAgreement : CAPI::CNG::BKeyAgreement
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::BigEndian; 
		   
	    // алгоритм хэширования и идентификатор алгоритма шифрования ключа
		private: CAPI::CNG::Hash^ hashAlgorithm; private: String^ wrapOID; 

		// конструктор
		public: BKeyAgreement(String^ provider, CAPI::CNG::Hash^ hashAlgorithm, String^ wrapOID) 
			
			: CAPI::CNG::BKeyAgreement(provider) 
		{
			// сохранить переданные параметры
			this->hashAlgorithm = RefObject::AddRef(hashAlgorithm); this->wrapOID = wrapOID;
		}
		// декструктор
		public: virtual ~BKeyAgreement() { RefObject::Release(hashAlgorithm); }

        // сгенерировать случайные данные
		public: virtual array<BYTE>^ Generate(IParameters^ parameters, IRand^ rand) override
		{
			// создать буфер для случайных данных
			array<BYTE>^ random = gcnew array<BYTE>(64); 
			
			// сгенерировать случайные данные
			rand->Generate(random, 0, random->Length); return random; 
		}
		// имя алгоритма
		protected: virtual String^ GetName(IParameters^ parameters) override { return BCRYPT_DH_ALGORITHM; }

		// импортировать личный ключ
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPrivateKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) override; 

		// импортировать открытый ключ
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPublicKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) override; 

	    // согласовать общий ключ на стороне получателя
		protected: virtual array<BYTE>^ DeriveKey(IParameters^ parameters, 
			CAPI::CNG::BSecretHandle^ hSecret, array<BYTE>^ random, int keySize) override; 
	};
}}}}}}}
