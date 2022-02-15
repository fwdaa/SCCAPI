#pragma once
#include "SCardStores.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Athena 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� Athena
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : Microsoft::RSA::AESEnhancedProvider
	{
		// �����������
		public: Provider() : Microsoft::RSA::AESEnhancedProvider(
			PROV_RSA_FULL, "Athena ASECard Crypto CSP", false, true) {}

		// ��� ����������
		public: virtual property String^ Name 
		{ 
			// ��� ����������
			String^ get() override { return CAPI::CSP::Provider::Name; }
		}
		// ����������� ��������� ����������
		public: virtual array<String^>^ EnumerateStores(Scope scope) override
		{
			// ������� ������ ����
			return gcnew array<String^> { "Card" }; 
		}
		// �������� ��������� ����������
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// ��������� ��� ���������
			if (name != "Card") throw gcnew NotFoundException(); 

			// ������� ��������� �����������
			return gcnew SCardStores(this, scope); 
		}
		// ������� �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override;
	};
}}}}}
