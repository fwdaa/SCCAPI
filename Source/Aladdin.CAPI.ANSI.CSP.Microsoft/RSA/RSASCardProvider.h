#pragma once
#include "AESEnhancedProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Base Smart Card
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardProvider : AESEnhancedProvider
	{
		// �����������
		public: SCardProvider() : AESEnhancedProvider(PROV_RSA_FULL, MS_SCARD_PROV_W, false, false) {}

		// ��� ������
		public: virtual property String^ Group { String^ get() override { return Name; }}
		// ��� ����������
		public: virtual property String^ Name { String^ get() override { return Provider::Name; }}

		// ����������� ��������� ����������
		public: virtual array<String^>^ EnumerateStores(Scope scope) override
		{
			// ������� ������ ����
			return gcnew array<String^> { "Card" }; 
		}
		// �������� ��������� ����������
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// ������� ��������� �����������
			return gcnew CAPI::CSP::SCardStores(this, scope, 0); 
		}
		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;
	};
}}}}}}
