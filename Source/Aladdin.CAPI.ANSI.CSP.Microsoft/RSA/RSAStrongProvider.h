#pragma once
#include "RSAEnhancedProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Strong Cryptographic Provider
	///////////////////////////////////////////////////////////////////////////
	public ref class StrongProvider : EnhancedProvider
	{
		// �����������
		public: StrongProvider() : EnhancedProvider(PROV_RSA_FULL, MS_STRONG_PROV_W, false, true) {}

		// �����������
		protected: StrongProvider(DWORD type, String^ name, bool sspi, bool oaep) 
		
			// ��������� ���������� ���������
			: EnhancedProvider(type, name, sspi, oaep) {}

		// ��� ����������
		public: virtual property String^ Name { String^ get() override { return Provider::Name; }}
	}; 
}}}}}}
