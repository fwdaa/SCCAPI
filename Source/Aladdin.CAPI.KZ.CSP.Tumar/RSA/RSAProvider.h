#pragma once
#include "..\Provider.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Tumar CSP RSA
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : Tumar::Provider
	{
		// конструктор
		public: Provider() : Tumar::Provider(PROV_TUMAR_RSA, GT_RSA_PROV, true) {}
	};
}}}}}}

