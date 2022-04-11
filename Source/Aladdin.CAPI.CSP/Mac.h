#pragma once
#include "Provider.h"
#include "Cipher.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////
	// Алгоритм выработки имитовставки
	///////////////////////////////////////////////////////////////////////
	public ref class Mac abstract : CAPI::Mac
	{
        private: CSP::Provider^		provider;   // криптографический провайдер
		private: ContextHandle^		hContext;	// криптографический контекст
		private: Using<KeyHandle^>	hKey;		// ключ для вычисления имитовставки 
		private: Using<HashHandle^> hHash;		// алгоритм вычисления имитовставки 
        private: DWORD				flags;      // дополнительные флаги создания ключа
		
		// конструктор
		protected: Mac(CSP::Provider^ provider, ContextHandle^ hContext, DWORD flags) 
		{ 
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); 
			
			// сохранить переданные параметры
			this->hContext = Handle::AddRef(hContext); this->flags = flags; 	
		}
		// деструктор
        public: virtual ~Mac() 
		{ 
			// освободить используемые ресурсы
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// криптографические провайдер и контекст
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
    
		// идентификатор алгоритма хэширования
		protected: virtual property ALG_ID AlgID { ALG_ID get() = 0; }

		// установить параметры алгоритма
		protected: virtual void SetParameters(KeyHandle^ hKey) {} 

		// создать алгоритм вычисления имитовставки
		protected: virtual HashHandle^ Construct(ContextHandle^ hContext, KeyHandle^ hKey)
		{
			// создать алгоритм вычисления имтовставки
			return hContext->CreateHash(AlgID, hKey, 0); 
		} 
		// инициализировать алгоритм
		public: virtual void Init(ISecretKey^ key) override; 
		// захэшировать данные
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override; 
		// получить имитовставку
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override; 
	};
	///////////////////////////////////////////////////////////////////////
	// CBC-MAC
	///////////////////////////////////////////////////////////////////////
	public ref class CBC_MAC : Mac
	{
		// блочный алгоритм шифрования и вектор инициализации
		private: BlockCipher^ blockCipher; private: array<BYTE>^ iv; 

		// конструктор
		public: CBC_MAC(BlockCipher^ blockCipher, array<BYTE>^ iv) 
			
			// сохранить переданные параметры
			: Mac(blockCipher->Provider, blockCipher->Context, 0)
		{ 
			// сохранить переданные параметры
			this->blockCipher = RefObject::AddRef(blockCipher); this->iv = iv; 
		}
		// деструктор
        public: virtual ~CBC_MAC() { RefObject::Release(blockCipher); }

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return blockCipher->KeyFactory; }
		}
		// размер MAC-значения
		public: virtual property int MacSize 
		{ 
			// размер MAC-значения
			int get() override { return blockCipher->BlockSize; }
		} 
		// размер блока
		public: virtual property int BlockSize 
		{ 
			// размер MAC-значения
			int get() override { return blockCipher->BlockSize; }
		} 
		// идентификатор алгоритма
		protected: virtual property ALG_ID AlgID 
		{ 
			// идентификатор алгоритма
			ALG_ID get() override { return CALG_MAC; }
		}
		// установить параметры алгоритма
		protected: virtual void SetParameters(KeyHandle^ hKey) override 
		{
			// установить параметры алгоритма
			blockCipher->SetParameters(hKey); 

			// установить режим шифрования и синхропосылку
			// hKey->SetLong(KP_MODE, CRYPT_MODE_CBC, 0); hKey->SetParam(KP_IV, iv, 0);

			// указать способ дополнения
			// hKey->SetLong(KP_PADDING, PKCS5_PADDING, 0);
		} 
	}; 
}}}

