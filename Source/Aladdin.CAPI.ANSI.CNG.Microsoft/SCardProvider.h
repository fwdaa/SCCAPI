#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// ����������������� ��������� ��� �����-����
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardProvider : Provider
	{
		// �����������
		public: SCardProvider() : Provider("Microsoft Smart Card Key Storage Provider") {}

		// �������� ��������� ����������
		public: virtual array<String^>^ EnumerateStores(Scope scope) override 
		{ 
			// ������� ������ ����
			return gcnew array<String^> { "Card" }; 
		}
		// �������� ��������� ����������
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// ������� ��������� �����������
			return gcnew CAPI::CNG::SCardStores(this, scope, 0); 
		}
	};
}}}}}
