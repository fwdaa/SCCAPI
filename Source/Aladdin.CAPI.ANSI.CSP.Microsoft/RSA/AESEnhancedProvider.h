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
		public: AESEnhancedProvider() : StrongProvider(PROV_RSA_AES, nullptr, false, true)
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("AES", gcnew Keys::AES()); 
		}
		// конструктор
		protected: AESEnhancedProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// сохранить переданные параметры
			: StrongProvider(type, name, sspi, oaep) 
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("AES", gcnew Keys::AES()); 
		}
		// имя группы
		public: virtual property String^ Group { String^ get() override { return Name; }}

		// имя провайдера
		public: virtual property String^ Name { String^ get() override
		{
			// вернуть имя провайдера
			return "Microsoft Enhanced RSA and AES Cryptographic Provider"; 
		}}
		// вернуть тип ключа
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override;

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
