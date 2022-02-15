#pragma once
#include "SCardStore.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace AKS 
{
	///////////////////////////////////////////////////////////////////////////
	// �����-����� ��� ���������� ��������
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStores : CAPI::CSP::SCardStores
	{
		// �����������
		public: SCardStores(CAPI::CSP::Provider^ provider, CAPI::Scope scope)

			// ��������� ���������� ���������
			: CAPI::CSP::SCardStores(provider, scope, 0) {}

		// ������� ��������� 
		public: virtual SecurityObject^ OpenObject(Object^ name, FileAccess access) override
		{
			// ������� �����-�����
			return SCardStore::Create(this, name->ToString()); 
		}
	};
}}}}}
