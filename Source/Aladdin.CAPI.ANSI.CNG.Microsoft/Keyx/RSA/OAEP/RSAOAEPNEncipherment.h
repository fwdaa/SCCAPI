#pragma once
#include "..\PKCS1\RSAPKCS1NEncipherment.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace OAEP
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных OAEP
    ///////////////////////////////////////////////////////////////////////
	public ref class NEncipherment : RSA::PKCS1::NEncipherment
	{
		// идентификатор алгоритма хэширования и метка
		private: String^ hashOID; private: int hashSize; private: array<BYTE>^ label; 

		// конструктор
		public: NEncipherment(CAPI::CNG::NProvider^ provider, String^ hashOID, array<BYTE>^ label);  

		// зашифровать данные
		protected: virtual array<BYTE>^ Encrypt(
			CAPI::CNG::NKeyHandle^ hPublicKey, array<BYTE>^ data) override;
	};
}}}}}}}}
