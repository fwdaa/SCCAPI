#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ����������������� ��������� �� �����-�����
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardContainer : Container
	{
        // �����������
		public: static SCardContainer^ Create(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
		{
			// ������� ������ ����������
			SCardContainer^ container = gcnew SCardContainer(store, name, mode); 

			// ������� ������
			try { return (SCardContainer^)Proxy::SecurityObjectProxy::Create(container); }

			// ���������� ��������� ������
			catch (Exception^) { delete container; throw; }
		}
		// �����������
		protected: SCardContainer(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
			
			// ��������� ���������� ���������
			: Container(store, name, mode) {}

		// ���������� ������� ������������� �� ���������
		public: virtual void SetDefaultStoreContainer() override
		{
			// ���������� ������� ������������� �� ���������
			Handle->SetLong(PP_CONTAINER_DEFAULT, 0, 0);
		} 
	}; 
}}}}
