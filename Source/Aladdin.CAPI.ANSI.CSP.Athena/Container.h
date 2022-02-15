#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Athena 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������� �� �����-�����
	///////////////////////////////////////////////////////////////////////////
	public ref class Container : CAPI::CSP::Container
	{
        // �����������
		public: static Container^ Create(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
		{
			// ������� ������ ����������
			Container^ container = gcnew Container(store, name, mode); 

			// ������� ������
			try { return (Container^)Proxy::SecurityObjectProxy::Create(container); }

			// ���������� ��������� ������
			catch (Exception^) { delete container; throw; }
		}
		// �����������
		protected: Container(CAPI::CSP::ProviderStore^ store, String^ name, DWORD mode) 
			
			// ��������� ���������� ���������
			: CAPI::CSP::Container(store, name, mode) {}

		// ���������� ������� ������������� �� ���������
		public: virtual void SetDefaultStoreContainer() override
		{
			// ���������� ������� ������������� �� ���������
			Handle->SetLong(PP_CONTAINER, 0, 0);
		} 
	}; 
}}}}}
