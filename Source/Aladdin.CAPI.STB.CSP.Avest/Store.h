#pragma once

using namespace System::IO; 

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// ���������� ������������
	///////////////////////////////////////////////////////////////////////////
	public ref class SCardStore : CAPI::CSP::ProviderStore
	{
		// ����� ���-�������
		private: static AuthenticationCache^ Cache = gcnew AuthenticationCache(false); 

		// �����������
		public: SCardStore(CAPI::CSP::Provider^ provider) 
            : CAPI::CSP::ProviderStore(provider, CAPI::KeyFlags::None, Cache) {} 
	};
}}}}}