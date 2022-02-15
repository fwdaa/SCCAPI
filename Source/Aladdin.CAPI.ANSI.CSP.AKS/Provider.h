#pragma once
#include "SCardStores.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace AKS 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� eToken Base
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider : Microsoft::RSA::AESEnhancedProvider
	{
		// �����������
		public: Provider() : Microsoft::RSA::AESEnhancedProvider(
			PROV_RSA_FULL, "eToken Base Cryptographic Provider", false, false) {}

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
	};
}}}}}