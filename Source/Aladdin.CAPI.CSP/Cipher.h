#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class Cipher abstract : CAPI::Cipher
	{
		// криптографические провайдер и контекст
		private: CSP::Provider^ provider; private: ContextHandle^ hContext; 

		// конструктор
		protected: Cipher(CSP::Provider^ provider, ContextHandle^ hContext) 
		{  
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); 
			
			// сохранить переданные параметры
			this->hContext = Handle::AddRef(hContext); 
		} 
		// деструктор
		public: virtual ~Cipher() 
		{ 
			// освободить выделенные ресурсы
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// криптографические провайдер и контекст
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
    
		// установить параметры алгоритма
		public protected: virtual void SetParameters(KeyHandle^ hKey, PaddingMode padding) {} 

		// алгоритм зашифрования данных
		protected: virtual Transform^ CreateEncryption(ISecretKey^ key) override; 
		// алгоритм расшифрования данных
		protected: virtual Transform^ CreateDecryption(ISecretKey^ key) override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// Блочный алгоритм шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockCipher abstract : RefObject, IBlockCipher
	{
		// криптографические провайдер и контекст
		private: CSP::Provider^ provider; private: ContextHandle^ hContext; 

		// конструктор
		protected: BlockCipher(CSP::Provider^ provider, ContextHandle^ hContext) 
		{  
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); 
			
			// сохранить переданные параметры
			this->hContext = Handle::AddRef(hContext); 
		} 
		// деструктор
		public: virtual ~BlockCipher() 
		{ 
			// освободить выделенные ресурсы
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// криптографические провайдер и контекст
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory { SecretKeyFactory^ get() = 0; }
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes { array<int>^ get() = 0; }
		// размер блока
		public: virtual property int BlockSize { int get()  = 0; }

		// создать режим шифрования
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode); 

		// установить параметры алгоритма
		public protected: virtual void SetParameters(KeyHandle^ hKey) {} 
	};
	///////////////////////////////////////////////////////////////////////////
	// Режим блочного алгоритма шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockMode : Cipher
	{
		// блочный алгоритм шифрования
		private: BlockCipher^ blockCipher; 
		// режим алгоритма и способ дополнения
		private: CipherMode^ mode; private: PaddingMode padding; 

		// конструктор
		public: BlockMode(BlockCipher^ blockCipher, CipherMode^ mode, PaddingMode padding) 

			// сохранить переданные параметры
			: Cipher(blockCipher->Provider, blockCipher->Context)
		{
			// сохранить переданные параметры
			this->blockCipher = RefObject::AddRef(blockCipher); 

			// сохранить переданные параметры
			this->mode = mode; this->padding = padding; 
		}
		// деструктор
		public: virtual ~BlockMode() { RefObject::Release(blockCipher); }

        // режим алгоритма
		public: virtual property CipherMode^ Mode { CipherMode^	get() override { return mode; }}	
		// способ дополнения
		public: property PaddingMode Padding { PaddingMode get() { return padding; }}	

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory 
		{ 
			// тип ключа
			SecretKeyFactory^ get() override { return blockCipher->KeyFactory; } 
		}
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes 
		{ 
			// размер ключа в байтах
			array<int>^ get() override { return blockCipher->KeySizes; }
		}
		// размер блока
		public: virtual property int BlockSize 
		{ 
			// размер блока
			int get() override { return blockCipher->BlockSize; }
		}
		// алгоритм зашифрования данных
		public: virtual Transform^ CreateEncryption(ISecretKey^ key, PaddingMode padding) override; 
		// алгоритм расшифрования данных
		public: virtual Transform^ CreateDecryption(ISecretKey^ key, PaddingMode padding) override; 

		// алгоритм зашифрования данных
		protected: virtual Transform^ CreateEncryption(ISecretKey^ key) override; 
		// алгоритм расшифрования данных
		protected: virtual Transform^ CreateDecryption(ISecretKey^ key) override; 

		// установить параметры алгоритма
		public protected: virtual void SetParameters(KeyHandle^ hKey, PaddingMode padding) override; 

        // указать режим дополнения
		protected: virtual BlockPadding^ GetPadding();  
	};
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class Encryption : Transform
	{
		private: Cipher^			cipher;		// алгоритм шифрования
		private: PaddingMode		padding;	// режим дополнения
		private: ISecretKey^		key;		// значение ключа шифрования
		private: Using<KeyHandle^>	hKey;		// описатель ключа

		// конструктор
		public: Encryption(Cipher^ cipher, PaddingMode padding, ISecretKey^ key) 
		{
			// сохранить переданные параметры
            this->cipher = RefObject::AddRef(cipher); 
			
			// сохранить переданные параметры
			this->padding = padding; this->key = RefObject::AddRef(key); 
		}
		// деструктор
		public: virtual ~Encryption() 
		{ 
			// освободить выделенные ресурсы
			RefObject::Release(key); RefObject::Release(cipher); 
		}
		// размер блока алгоритма
		public: virtual property int BlockSize  { int get() override { return cipher->BlockSize; }}
		// способ дополнения 
		public: virtual property PaddingMode Padding 
		{ 
			// способ дополнения 
			PaddingMode get() override { return padding; }
		}
		// инициализировать алгоритм
		public: virtual void Init() override; 
		// зашифровать данные
		public: virtual int Update(array<BYTE>^ data, 
			int dataOff, int dataLen, array<BYTE>^ buf, int bufOff) override; 
		// завершить зашифрование данных
		public:	virtual int Finish(array<BYTE>^ data, 
			int dataOff, int dataLen, array<BYTE>^ buf, int bufOff) override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм расшифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class Decryption : Transform
	{
		private: Cipher^			cipher;		// алгоритм шифрования
		private: PaddingMode		padding;	// режим дополнения
		private: ISecretKey^		key;		// значение ключа шифрования
		private: Using<KeyHandle^>	hKey;		// описатель ключа
		private: array<BYTE>^		lastBlock;	// значение последнего блока   

		// конструктор
		public: Decryption(Cipher^ cipher, PaddingMode padding, ISecretKey^ key) 
		{
			// сохранить переданные параметры
            this->cipher = RefObject::AddRef(cipher); this->padding = padding;

			// сохранить переданные параметры
			this->key = RefObject::AddRef(key); lastBlock = nullptr; 
		}
		// деструктор
		public: virtual ~Decryption() 
		{ 
			// освободить выделенные ресурсы
			RefObject::Release(key); RefObject::Release(cipher); 
		}
		// размер блока алгоритма
		public: virtual property int BlockSize { int get() override { return cipher->BlockSize; }}
		// способ дополнения 
		public: virtual property PaddingMode Padding 
		{ 
			// способ дополнения 
			PaddingMode get() override { return padding; }
		}
		// инициализировать алгоритм
		public: virtual void Init() override; 
		// расшифровать данные
		public: virtual int Update(array<BYTE>^ data, 
			int dataOff, int dataLen, array<BYTE>^ buf, int bufOff) override; 
		// завершить расшифрование
		public: virtual int Finish(array<BYTE>^ data, 
			int dataOff, int dataLen, array<BYTE>^ buf, int bufOff) override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм наследования ключа
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyDerive abstract : CAPI::KeyDerive
	{
		// криптографические провайдер и контекст
		private: CSP::Provider^ provider; private: ContextHandle^ hContext; 

		// конструктор
		public: KeyDerive(CSP::Provider^ provider, ContextHandle^ hContext)
        {   
            // сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); 

			// сохранить переданные параметры
			this->hContext = Handle::AddRef(hContext); 
		}
        // деструктор
		public: virtual ~KeyDerive() 
		{ 
			// освободить выделенные ресурсы
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// криптографические провайдер и контекст
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования ключа
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyWrap abstract : CAPI::KeyWrap
	{
		// криптографические провайдер и контекст
		private: CSP::Provider^ provider; private: ContextHandle^ hContext; 

		// конструктор
		public: KeyWrap(CSP::Provider^ provider, ContextHandle^ hContext)
        {   
            // сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); 

			// сохранить переданные параметры
			this->hContext = Handle::AddRef(hContext); 
		}
        // деструктор
		public: virtual ~KeyWrap() 
		{ 
			// освободить выделенные ресурсы
			Handle::Release(hContext); RefObject::Release(provider); 
		}
		// криптографические провайдер и контекст
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
	};
}}}
