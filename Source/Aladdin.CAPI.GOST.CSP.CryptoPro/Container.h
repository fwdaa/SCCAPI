#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ����������������� ���������
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

		// ������������� ����
		public protected: virtual CAPI::CSP::KeyHandle^ GenerateKeyPair(
			IntPtr hwnd, ALG_ID keyType, DWORD flags) override;

		// ������� ����� ����������
		public: virtual void DeleteKeys() override
		{
			// ������� ����� ���������� � ������� ������ ���������
			CAPI::CSP::Container::DeleteKeys(); Synchronize(); 
		}
		// ������� ���������
		public: void Delete() { Handle->SetParam(PP_DELETE_KEYSET, IntPtr::Zero, 0); }

		// ��������� �������������
		public: void Synchronize() { Handle->GetLong(PP_HCRYPTPROV, 0); }
	}; 
}}}}}
