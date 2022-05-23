#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace ECDH
{
	//////////////////////////////////////////////////////////////////////////////
	// Алгоритм согласования общего ключа
	//////////////////////////////////////////////////////////////////////////////
	public ref class NKeyAgreement : CAPI::CNG::NKeyAgreement
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::BigEndian; 

		// алгоритм хэширования и идентификатор алгоритма шифрования ключа
		private: CAPI::CNG::Hash^ hashAlgorithm; ASN1::ISO::AlgorithmIdentifier^ wrapParameters;

		// конструктор
		public: NKeyAgreement(CAPI::CNG::Hash^ hashAlgorithm, 
			ASN1::ISO::AlgorithmIdentifier^ wrapParameters)
		{
			// сохранить переданные параметры
			this->hashAlgorithm = RefObject::AddRef(hashAlgorithm); 

			// сохранить переданные параметры
            this->wrapParameters = wrapParameters;
		}
		// декструктор
		public: virtual ~NKeyAgreement() { RefObject::Release(hashAlgorithm); }

        // сгенерировать случайные данные
		public: virtual array<BYTE>^ Generate(IParameters^ parameters, IRand^ rand) override
		{
			// создать буфер для случайных данных
			array<BYTE>^ random = gcnew array<BYTE>(64); 
			
			// сгенерировать случайные данные
			rand->Generate(random, 0, random->Length); return random; 
		}
	    // согласовать общий ключ на стороне получателя
		protected: virtual array<BYTE>^ DeriveKey(IParameters^ parameters, 
			CAPI::CNG::NSecretHandle^ hSecret, array<BYTE>^ random, int keySize) override; 
	};
}}}}}}

