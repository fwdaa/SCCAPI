#pragma once
#include "RSABaseProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Enhanced Cryptographic Provider
	///////////////////////////////////////////////////////////////////////////
	public ref class EnhancedProvider : BaseProvider
	{
		// конструктор
		public: EnhancedProvider() : BaseProvider(PROV_RSA_FULL, MS_ENHANCED_PROV_W, false, true) 
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()["RC2"] = gcnew Keys::RC2 (KeySizes::Range(5, 16)); 
			SecretKeyFactories()["RC4"] = gcnew Keys::RC4 (KeySizes::Range(5, 16)); 

			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("DESede", gcnew Keys::TDES()); 
		}
		// конструктор
		protected: EnhancedProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// сохранить переданные параметры
			: BaseProvider(type, name, sspi, oaep) 
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()["RC2"] = gcnew Keys::RC2 (KeySizes::Range(5, 16)); 
			SecretKeyFactories()["RC4"] = gcnew Keys::RC4 (KeySizes::Range(5, 16)); 

			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("DESede", gcnew Keys::TDES()); 
		}
		// имя провайдера
		public: virtual property String^ Name { String^ get() override 
		{ 
			// имя провайдера
			return "Microsoft Enhanced Cryptographic Provider"; 
		}}
		// определить тип ключа
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override; 

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
