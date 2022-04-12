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

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
