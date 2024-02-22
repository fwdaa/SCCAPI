#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ����������������� ��������� � �������
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryContainer : Container
	{
        // �����������
		public: static RegistryContainer^ Create(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
		{
			// ������� ������ ����������
			RegistryContainer^ container = gcnew RegistryContainer(store, name, mode); 

			// ������� ������
			try { return (RegistryContainer^)Proxy::SecurityObjectProxy::Create(container); }

			// ���������� ��������� ������
			catch (Exception^) { delete container; throw; }
		}
		// �����������
		protected: RegistryContainer(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
			
			// ��������� ���������� ���������
			: Container(store, name, mode) {}

		// ��������� ������� ���������� ��������������
		public: virtual bool IsAuthenticationRequired(Exception^ e) override; 

		// ������� �������� ��������������
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override; 
	}; 
}}}}
