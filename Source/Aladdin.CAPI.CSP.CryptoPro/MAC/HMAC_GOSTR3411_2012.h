#pragma once
#include "..\Hash\GOSTR3411_2012.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro { namespace MAC
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм HMAC ГОСТ Р 34.11-2012
	///////////////////////////////////////////////////////////////////////////
	public ref class HMAC_GOSTR3411_2012 : CAPI::CSP::Mac
	{
		// алгоритм HMAC
		private: int bits; private: Hash::GOSTR3411_2012 hash; Using<CAPI::Mac^> hMAC; 

		// конструктор
		public: HMAC_GOSTR3411_2012(CAPI::CSP::Provider^ provider, 
			CAPI::CSP::ContextHandle^ hContext, int bits) 

			// сохранить переданные параметры
			: CAPI::CSP::Mac(provider, hContext, 0), hash(provider, hContext, bits) 
		{ 
			// сохранить переданные параметры
			this->bits = bits; 
		}
		// деструктор
		public: virtual ~HMAC_GOSTR3411_2012() {}

        // идентификатор алгоритма
		protected: virtual property ALG_ID AlgID { ALG_ID get() override 
		{ 
			// вернуть идентификатор алгоритма
			return (bits == 256) ? CALG_GR3411_2012_256_HMAC : CALG_GR3411_2012_512_HMAC; 
		}}
		// размер имитовставки
		public:	virtual property int MacSize { int get() override { return bits / 8; }}  
		// размер имитовставки
		public:	virtual property int BlockSize { int get() override { return hash.BlockSize; }}  

		// инициализировать алгоритм
		public: virtual void Init(ISecretKey^ key) override; 
		// захэшировать данные
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override
		{
			// вызвать базовую функцию
			if (hMAC.Get() == nullptr) CAPI::CSP::Mac::Update(data, dataOff, dataLen); 

			// захэшировать данные
			else hMAC.Get()->Update(data, dataOff, dataLen);
		}
		// получить имитовставку
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override
		{
			// вызвать базовую функцию
			if (hMAC.Get() == nullptr) return CAPI::CSP::Mac::Finish(buffer, bufferOff); 

			// получить имитовставку
			int length = hMAC.Get()->Finish(buffer, bufferOff); 

			// освободить выделенные ресурсы
			hMAC.Close(); return length; 
		}
	}; 
}}}}}