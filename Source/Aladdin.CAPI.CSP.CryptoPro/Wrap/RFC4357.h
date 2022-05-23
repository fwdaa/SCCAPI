#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace Wrap
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования ключа ГОСТ 28147-89
	///////////////////////////////////////////////////////////////////////////
	public ref class RFC4357 abstract : CAPI::CSP::KeyWrap
	{
		// идентификатор таблицы подстановок и случайные данные    
		private: String^ sboxOID; private: array<BYTE>^ ukm; 

		// конструктор
		protected: RFC4357(CAPI::CSP::Provider^ provider, CAPI::CSP::ContextHandle^ hContext, 
			
            // сохранить переданные параметры
			String^ sboxOID, array<BYTE>^ ukm) : CAPI::CSP::KeyWrap(provider, hContext)
		{
            // сохранить переданные параметры
			this->sboxOID = sboxOID; this->ukm = ukm;
		}
		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return GOST::Keys::GOST::Instance; }
		}
	    // получить алгоритм диверсификации ключа
		public: virtual CAPI::KeyDerive^ GetKDFAlgorithm(CAPI::CSP::ContextHandle^ hContext) = 0; 

		// зашифровать ключ
		public: virtual array<BYTE>^ Wrap(IRand^ rand, ISecretKey^ key, ISecretKey^ CEK) override; 
		// расшифровать ключ
		public: virtual ISecretKey^ Unwrap(ISecretKey^ key, 
			array<BYTE>^ wrappedCEK, SecretKeyFactory^ keyFactory) override; 

		// идентификатор алгоритма 
		protected: virtual property ALG_ID  AlgID { ALG_ID  get() = 0; }

        // идентификатор таблицы подстановок
		protected: virtual property String^ SBoxOID { String^ get() { return sboxOID; } }

		///////////////////////////////////////////////////////////////////////
		// Вспомогательные функции
		///////////////////////////////////////////////////////////////////////
		internal: static array<BYTE>^ WrapKey(ALG_ID algID, array<BYTE>^ ukm, 
			CAPI::CSP::KeyHandle^ hKEK, CAPI::CSP::KeyHandle^ hCEK
		); 
		internal: static CAPI::CSP::KeyHandle^ UnwrapKey(
			CAPI::CSP::ContextHandle^ hContext, ALG_ID algID, 
			array<BYTE>^ ukm, CAPI::CSP::KeyHandle^ hKEK, array<BYTE>^ wrappedCEK
		); 
	};
}}}}}
