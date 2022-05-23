#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar
{
	///////////////////////////////////////////////////////////////////////////
	// Тип ключа шифрования
	///////////////////////////////////////////////////////////////////////////
	public ref class SecretKeyType : Microsoft::SecretKeyType
	{
		// конструктор
		public: SecretKeyType(ALG_ID algID) : Microsoft::SecretKeyType(algID) {}

		// создать ключ для алгоритма шифрования
		public: virtual CAPI::CSP::KeyHandle^ ConstructKey(
			CAPI::CSP::ContextHandle^ hContext, array<BYTE>^ value, DWORD flags) override; 

		// получить значение ключа
		public: virtual array<BYTE>^ GetKeyValue(
			CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) override; 
	};
}}}}
