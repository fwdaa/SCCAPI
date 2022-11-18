#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� ��������� 2012
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider2012_512 : Provider
	{
		// �����������
		public: Provider2012_512() : Provider(PROV_GOST_2012_512) {} 

	    // ������������ �����
		public: virtual array<String^>^ GeneratedKeys(SecurityStore^ store) override
		{
			// ������� ������������ �����
			return gcnew array<String^> { ASN1::GOST::OID::gostR3410_2012_512 }; 
		}
		// ������� �������� ��������� ������
		public protected: virtual CAPI::KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 
	};
}}}}