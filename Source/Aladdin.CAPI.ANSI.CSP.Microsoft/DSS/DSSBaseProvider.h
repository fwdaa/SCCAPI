#pragma once
#include "DSSProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace DSS 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Base DSS and Diffie-Hellman
	///////////////////////////////////////////////////////////////////////////
	public ref class BaseProvider : Provider
	{
		// конструктор
		public: BaseProvider() : Provider(PROV_DSS_DH, MS_DEF_DSS_DH_PROV_W, false) 
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("RC2" , gcnew Keys::RC2 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("RC4" , gcnew Keys::RC4 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("DES" , gcnew Keys::DES (                     )); 
			SecretKeyFactories()->Add("DESX", gcnew Keys::DESX(                     )); 
		}
		// конструктор
		protected: BaseProvider(DWORD type, String^ name, bool sspi) : Provider(type, name, sspi) 
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("RC2" , gcnew Keys::RC2 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("RC4" , gcnew Keys::RC4 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("DES" , gcnew Keys::DES (                     )); 
			SecretKeyFactories()->Add("DESX", gcnew Keys::DESX(                     )); 
		}
		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
