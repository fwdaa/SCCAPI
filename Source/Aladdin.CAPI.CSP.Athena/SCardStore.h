#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Athena 
{
	///////////////////////////////////////////////////////////////////////////
	// �����-����� ��� ���������� ��������
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : CAPI::CSP::SCardStore
	{
		// �����������
		public: static SCardStore^ Create(SecurityStore^ store, String^ name) 
		{
			// ������� ������ �����-�����
			SCardStore^ cardStore = gcnew SCardStore(store, name); 

			// ������� ������
			try { return (SCardStore^)Proxy::SecurityObjectProxy::Create(cardStore); }

			// ���������� ��������� ������
			catch (Exception^) { delete cardStore; throw; }
		}
		// �����������
		protected: SCardStore(SecurityStore^ store, String^ name) 
			
			// ��������� ���������� ���������
			: CAPI::CSP::SCardStore(store, Athena::Container::typeid, name, 0) {} 
	};
}}}}
