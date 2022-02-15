#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	ref class Provider;

	///////////////////////////////////////////////////////////////////////////
	// Фабрика создания ключей шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class SecretKeyType
	{
		// конструктор
		public: SecretKeyType(ALG_ID algID)

			// сохранить переданные параметры
			{ this->algID = algID; } private: ALG_ID algID; 

		// идентификатор алгоритма
		public: property ALG_ID AlgID { ALG_ID get() { return algID; }}

		// создать ключ для алгоритма шифрования
		public: virtual KeyHandle^ ConstructKey(
			ContextHandle^ hContext, array<BYTE>^ value, DWORD flags
		); 
		// получить значение ключа
		public: virtual array<BYTE>^ GetKeyValue(
			ContextHandle^ hContext, KeyHandle^ hKey
		); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Ключ шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class SecretKey : RefObject, ISecretKey
	{
        // провайдер, тип и описатель ключа
		private: CSP::Provider^ provider; private: SecretKeyFactory^ keyFactory; private: KeyHandle^ hKey; 

		// конструктор 
		public: SecretKey(CSP::Provider^ provider, SecretKeyFactory^ keyFactory, KeyHandle^ hKey);
		// деструктор
		public: virtual ~SecretKey(); private: array<BYTE>^ value; 

        // провайдер ключа
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }} 
		// описатель ключа
		public: property KeyHandle^ Handle { KeyHandle^ get() { return hKey; }} 

		// тип ключа
		public: virtual property SecretKeyFactory^ KeyFactory { SecretKeyFactory^ get() { return keyFactory; }}
        // размер ключа
        public: virtual property int Length { int get(); }
        // значение ключа
		public: virtual property array<BYTE>^ Value { array<BYTE>^ get(); }
	};
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ асимметричного алгоритма
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::PrivateKey
	{
		// параметры и идентификатор ключа
		private: IParameters^ parameters; array<BYTE>^ keyID;  
		// описатель ключа и тип ключа
		private: KeyHandle^	hPrivateKey; DWORD keyType; 

		// конструктор 
		public protected: PrivateKey(Provider^ provider, SecurityObject^ scope, 
			IPublicKey^ publicKey, KeyHandle^ hPrivateKey, array<BYTE>^ keyID, DWORD keyType
		);  
		// деструктор
        public: virtual ~PrivateKey() { Handle::Release(hPrivateKey); } 

		// параметры ключа
		public: virtual property IParameters^ Parameters 
		{ 
			// параметры ключа
			IParameters^ get() override { return parameters; }  
		}
		// получить описатель ключа
		public: KeyHandle^ OpenHandle(); 

		// идентификатор ключа
		public: property array<BYTE>^ KeyID { array<BYTE>^ get() { return keyID; }}
		// тип ключа
		public: property DWORD KeyType { DWORD get() { return keyType; }}

        // экспортировать ключ
        protected: array<BYTE>^ Export(KeyHandle^ hExportKey, DWORD flags); 
	};
}}}
