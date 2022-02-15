#pragma once
#include "RSAStrongProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер AES
	///////////////////////////////////////////////////////////////////////////
	public ref class AESEnhancedProvider : StrongProvider
	{
		// конструктор
		public: AESEnhancedProvider() : StrongProvider(PROV_RSA_AES, nullptr, false, true) {}

		// конструктор
		protected: AESEnhancedProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// сохранить переданные параметры
			: StrongProvider(type, name, sspi, oaep) {}

		// имя группы
		public: virtual property String^ Group { String^ get() override { return Name; }}

		// имя провайдера
		public: virtual property String^ Name { String^ get() override
		{
			// вернуть имя провайдера
			return "Microsoft Enhanced RSA and AES Cryptographic Provider"; 
		}}
		// поддерживаемые фабрики кодирования ключей
		public: virtual array<SecretKeyFactory^>^ SecretKeyFactories() override
		{
			// поддерживаемые фабрики кодирования ключей
			return gcnew array<SecretKeyFactory^> { 
				ANSI::Keys::RC2 ::Instance, ANSI::Keys::RC4 ::Instance, 
				ANSI::Keys::DES ::Instance, ANSI::Keys::DESX::Instance, 
				ANSI::Keys::TDES::Instance, ANSI::Keys::AES ::Instance 
			}; 
		}
		// вернуть тип ключа
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override;

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;
	}; 
}}}}}}
