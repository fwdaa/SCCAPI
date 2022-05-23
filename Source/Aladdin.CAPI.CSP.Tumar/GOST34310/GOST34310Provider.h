#pragma once
#include "..\Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace GOST34310
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Tumar CSP GOST
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : Tumar::Provider
	{
		// конструктор
		public: Provider() : Tumar::Provider(PROV_TUMAR_DH, GT_TUMAR_PROV, true) {}
	};
}}}}}
