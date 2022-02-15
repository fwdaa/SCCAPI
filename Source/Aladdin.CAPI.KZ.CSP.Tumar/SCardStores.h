#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar 
{
	///////////////////////////////////////////////////////////////////////////
	// �����-����� ��� ���������� ��������
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStores : CAPI::CSP::ProviderStore
	{
		// �����������
		public: SCardStores(CAPI::CSP::Provider^ provider, CAPI::Scope scope)

			// ��������� ���������� ���������
			: CAPI::CSP::ProviderStore(provider, scope, "Card", Container::typeid, 0) {}

		// ������� ���������� ��������������
		public: virtual property bool HasAuthentication { bool get() override { return false; }}

		// ���������� ��� ���������� ��� ����������
		public: virtual String^ GetNativeContainerName(String^ name) override; 
		// ������������ �����������
		public: virtual array<String^>^ EnumerateObjects() override; 

		// ������� ������
		public: virtual SecurityObject^ CreateObject(IRand^ rand, 
			Object^ name, Object^ authenticationData, ...array<Object^>^ parameters) override
        {
            // �������� �� ��������������
            throw gcnew InvalidOperationException(); 
        }
        // ������� ������
		public: virtual void DeleteObject(Object^ name, 
			array<CAPI::Authentication^>^ authentications) override
        {
            // �������� �� ��������������
            throw gcnew InvalidOperationException(); 
        }
	};
}}}}}
