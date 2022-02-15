#pragma once
#include "..\Hash\GOST34311.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace MAC 
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм HMAC ГОСТ Р 34.11-1994
	///////////////////////////////////////////////////////////////////////////
	public ref class HMAC_GOST34311 : CAPI::CSP::Mac
	{
		// идентификатор алгоритма и алгоритм HMAC
		private: ALG_ID algID; private: Hash::GOST34311 hash; Using<CAPI::Mac^> hMAC;

		// конструктор
		public: HMAC_GOST34311(CAPI::CSP::Provider^ provider, 
			CAPI::CSP::ContextHandle^ hContext, ALG_ID algID) 

			// сохранить переданные параметры
			: CAPI::CSP::Mac(provider, hContext, 0), 

			// создать алгоритм хэширования
			hash(provider, hContext, (algID == CALG_TGR3411_HMAC) ? CALG_TGR3411 : CALG_CPGR3411)
		{ 
			// сохранить переданные параметры
			this->algID = algID; 
		} 
		// деструктор
		public: virtual ~HMAC_GOST34311() {}

        // идентификатор алгоритма
		protected: virtual property ALG_ID AlgID { ALG_ID get() override { return algID; }}

		// размер имитовставки
		public:	virtual property int MacSize { int get() override { return 32; }}   
		// размер блока
		public:	virtual property int BlockSize { int get() override { return hash.BlockSize; }}   

		// инициализировать алгоритм
		public: virtual void Init(ISecretKey^ key) override; 
		// захэшировать данные
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override
		{
			// вызвать базовую функцию
			if (hMAC.Get() == nullptr) CAPI::CSP::Mac::Update(data, dataOff, dataLen);  

			// захэшировать данные
			else hMAC.Get()->Update(data, dataOff, dataLen); return;  
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
}}}}}}