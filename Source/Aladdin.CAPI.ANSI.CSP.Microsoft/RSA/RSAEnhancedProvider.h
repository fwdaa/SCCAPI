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
		public: EnhancedProvider() : BaseProvider(PROV_RSA_FULL, MS_ENHANCED_PROV_W, false, true) {}

		// конструктор
		protected: EnhancedProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// сохранить переданные параметры
			: BaseProvider(type, name, sspi, oaep) {}

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
