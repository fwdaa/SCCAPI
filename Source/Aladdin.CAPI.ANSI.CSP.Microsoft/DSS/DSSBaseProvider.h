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
		public: BaseProvider() : Provider(PROV_DSS_DH, MS_DEF_DSS_DH_PROV_W, false) {}

		// конструктор
		protected: BaseProvider(DWORD type, String^ name, bool sspi) : Provider(type, name, sspi) {}

		// получить алгоритмы по умолчанию
		public: virtual CAPI::Culture^ GetCulture(SecurityStore^ scope, String^ keyOID) override
        {
			// получить алгоритмы по умолчанию
			return (gcnew ANSI::Factory())->GetCulture(scope, keyOID); 
		}
		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;
	}; 
}}}}}}
