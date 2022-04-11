#pragma once
#include "DSSBaseProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace DSS 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Enhanced DSS and Diffie-Hellman
	///////////////////////////////////////////////////////////////////////////
	public ref class EnhancedProvider : BaseProvider
	{
		// конструктор
		public: EnhancedProvider() : BaseProvider(PROV_DSS_DH, MS_ENH_DSS_DH_PROV_W, false) 
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()["RC2"] = gcnew Keys::RC2 (KeySizes::Range(5, 16)); 
			SecretKeyFactories()["RC4"] = gcnew Keys::RC4 (KeySizes::Range(5, 16)); 

			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("DESede", gcnew Keys::TDES(gcnew array<int>{ 16, 24 })); 
		}
		// конструктор
		protected: EnhancedProvider(DWORD type, String^ name, bool sspi) 
		
			// сохранить переданные параметры
			: BaseProvider(type, name, sspi) 
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()["RC2"] = gcnew Keys::RC2 (KeySizes::Range(5, 16)); 
			SecretKeyFactories()["RC4"] = gcnew Keys::RC4 (KeySizes::Range(5, 16)); 

			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("DESede", gcnew Keys::TDES(gcnew array<int>{ 16, 24 })); 
		}
		// определить тип ключа
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override; 

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
