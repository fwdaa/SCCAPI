#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class Cipher abstract : CAPI::Cipher
	{
		// конструктор
		public: Cipher(String^ provider)
		
			// сохранить переданные параметры
			{ this->provider = provider; } private: String^ provider; 

		// имя провайдера
		public: property String^ Provider { String^ get() { return provider; }}

        // имя алгоритма шифрования
		public: virtual String^ GetName(int keySize) = 0; 
		// установить параметры алгоритма
		public protected: virtual array<BYTE>^ SetParameters(BProviderHandle^ hProvider) { return nullptr; } 

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
		// конструктор
		public: BlockCipher(String^ provider)

			// сохранить переданные параметры
			{ this->provider = provider; } private: String^ provider; 

		// имя провайдера
		public: property String^ Provider { String^ get() { return provider; }}

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory { SecretKeyFactory^ get() = 0; }
		// размер ключа в байтах
		public: virtual property array<int>^ KeySizes { array<int>^ get() = 0; }
		// размер блока
		public: virtual property int BlockSize { int get()  = 0; }

		// создать режим шифрования
		public: virtual CAPI::Cipher^ CreateBlockMode(CipherMode^ mode); 

        // имя алгоритма шифрования
		public: virtual String^ GetName(int keySize) = 0; 
		// установить параметры алгоритма
		public protected: virtual void SetParameters(BProviderHandle^ hProvider) {} 
	};
	///////////////////////////////////////////////////////////////////////////
	// Блочный алгоритм шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class BlockMode : Cipher
	{
		// блочный алгоритм шифрования, режим алгоритма и способ дополнения
		private: BlockCipher^ blockCipher; CipherMode^ mode; PaddingMode padding;

		// конструктор
		public: BlockMode(BlockCipher^ blockCipher, 
			CipherMode^ mode, PaddingMode padding) : Cipher(blockCipher->Provider)
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

        // имя алгоритма шифрования
		public: virtual String^ GetName(int keySize) override 
		{
			// имя алгоритма шифрования
			return blockCipher->GetName(keySize); 
		}
		// установить параметры алгоритма
		public protected: virtual array<BYTE>^ SetParameters(
			BProviderHandle^ hProvider) override; 

        // указать режим дополнения
		protected: virtual BlockPadding^ GetPadding(); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования
	///////////////////////////////////////////////////////////////////////////
	private ref class Encryption : Transform
	{
		private: Cipher^				 cipher;	// блочный алгоритм шифрования
		private: PaddingMode			 padding;	// режим дополнения блока
		private: array<BYTE>^			 key;		// значение ключа шифрования
		private: Using<BProviderHandle^> hProvider;	// криптографический контекст
		private: Using<BKeyHandle^>		 hKey;		// описатель ключа
		private: array<BYTE>^			 iv;		// текущее значение синхропосылки

		// конструктор
		public: Encryption(Cipher^ cipher, PaddingMode padding, array<BYTE>^ key)

			// создать криптографический контекст
			: hProvider(gcnew BProviderHandle(cipher->Provider, cipher->GetName(key->Length), 0))
		{
            // сохранить переданные параметры
			this->cipher = RefObject::AddRef(cipher); 
			 
            // сохранить переданные параметры
			this->padding = padding; this->key = key; this->iv = nullptr; 
		}
		// деструктор
		public: virtual ~Encryption() { RefObject::Release(cipher); }

		// размер блока алгоритма
		public: virtual property int BlockSize  { int get() override { return cipher->BlockSize;  }}
		// режим дополнения алгоритма
		public: virtual property PaddingMode Padding 
		{ 
			// режим дополнения алгоритма
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
	private ref class Decryption : Transform
	{
		private: Cipher^				 cipher;	// блочный алгоритм шифрования
		private: PaddingMode			 padding;	// режим дополнения блока
		private: array<BYTE>^			 key;		// значение ключа шифрования
		private: Using<BProviderHandle^> hProvider;	// криптографический контекст
		private: Using<BKeyHandle^>		 hKey;		// описатель ключа
		private: array<BYTE>^			 iv;		// текущее значение синхропосылки
		private: array<BYTE>^			 lastBlock;	// значение последнего блока   
		
		// конструктор
		public: Decryption(Cipher^ cipher, PaddingMode padding, array<BYTE>^ key) 

			// создать криптографический контекст
			: hProvider(gcnew BProviderHandle(cipher->Provider, cipher->GetName(key->Length), 0)) 
		{
            // сохранить переданные параметры
			this->cipher = RefObject::AddRef(cipher); this->padding = padding; 

            // сохранить переданные параметры
			this->key = key; this->iv = nullptr; this->lastBlock = nullptr; 
		}
		// деструктор
		public: virtual ~Decryption() { RefObject::Release(cipher); }

		// размер блока алгоритма
		public: virtual property int BlockSize { int get() override { return cipher->BlockSize; } }
		// режим дополнения алгоритма
		public: virtual property PaddingMode Padding 
		{ 
			// режим дополнения алгоритма
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
}}}
