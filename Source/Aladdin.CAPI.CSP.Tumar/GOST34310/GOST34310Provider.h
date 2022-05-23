#pragma once
#include "..\Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace GOST34310
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Tumar CSP GOST
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : Tumar::Provider
	{
		// �����������
		public: Provider() : Tumar::Provider(PROV_TUMAR_DH, GT_TUMAR_PROV, true) {}
	};
}}}}}
