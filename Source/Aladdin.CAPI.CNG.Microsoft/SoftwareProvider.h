#pragma once
#include "Provider.h"
#include "RegistryStore.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// ����������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class SoftwareProvider : Provider
	{
		// �����������
		public: SoftwareProvider() : Provider("Microsoft Software Key Storage Provider") {}

		// �������� ��������� ����������
		public: virtual array<String^>^ EnumerateStores(Scope scope) override 
		{ 
			// ������� ����� �������� �����������
			if (scope == Scope::System) return gcnew array<String^> { "HKLM" }; 
			if (scope == Scope::User  ) return gcnew array<String^> { "HKCU" }; 

			return gcnew array<String^>(0); 
		}
		// �������� ��������� ����������
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// ��������� ���������� �����
			if (scope == Scope::System && name != "HKLM")
			{
				// ��� ������ ��������� ����������
				throw gcnew NotFoundException(); 
			}
			// ��������� ���������� �����
			if (scope == Scope::User && name != "HKCU")
			{
				// ��� ������ ��������� ����������
				throw gcnew NotFoundException(); 
			}
			// ������� ��������� �����������
			return gcnew RegistryStore(this, scope);
		}
	};
}}}}