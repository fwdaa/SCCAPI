#pragma once
#include "..\Provider.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Tumar CSP RSA
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : Tumar::Provider
	{
		// �����������
		public: Provider() : Tumar::Provider(PROV_TUMAR_RSA, GT_RSA_PROV, true) {}
	};
}}}}}}

