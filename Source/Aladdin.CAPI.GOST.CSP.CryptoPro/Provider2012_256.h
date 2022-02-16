#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� ��������� 2012
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider2012_256 : Provider
	{
		// �����������
		public: Provider2012_256() : Provider(PROV_GOST_2012_256) {} 

	    // ������������ �����
		public: virtual array<String^>^ GeneratedKeys(SecurityStore^ store) override
		{
			// ������� ������������ �����
			return gcnew array<String^> { ASN1::GOST::OID::gostR3410_2012_256 }; 
		}
		// ������� �������� ��������� ������
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 
	}; 
}}}}}
