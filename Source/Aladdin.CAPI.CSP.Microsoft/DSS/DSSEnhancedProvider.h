#pragma once
#include "DSSBaseProvider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace DSS 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Enhanced DSS and Diffie-Hellman
	///////////////////////////////////////////////////////////////////////////
	public ref class EnhancedProvider : BaseProvider
	{
		// конструктор
		public: EnhancedProvider() : BaseProvider(PROV_DSS_DH, MS_ENH_DSS_DH_PROV_W, false) {}

		// конструктор
		protected: EnhancedProvider(DWORD type, String^ name, bool sspi) 
		
			// сохранить переданные параметры
			: BaseProvider(type, name, sspi) {}

		// определить тип ключа
		public: virtual CAPI::CSP::SecretKeyType^ GetSecretKeyType(
			SecretKeyFactory^ keyFactory, DWORD keySize) override; 

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}
