#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////
	// �������� �����������
	///////////////////////////////////////////////////////////////////////
	public ref class Hash abstract : CAPI::Hash
	{
		private: CSP::Provider^		provider;	// ����������������� ��������� 
		private: ContextHandle^		hContext;	// ����������������� �������� 
		private: Using<HashHandle^>	hHash;		// �������� ����������� 
		
		// �����������
		protected: Hash(CSP::Provider^ provider, ContextHandle^ hContext)
		{ 
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); 
			
			// ��������� ���������� ���������
			this->hContext = Handle::AddRef(hContext); 
		}
		// ����������
        public: virtual ~Hash() 
		{ 
			// ���������� ���������� �������
			Handle::Release(hContext); RefObject::Release(provider); 
		} 
        // ����������������� ��������� � ��������
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}
    
		// ������������� ���������
		public: virtual property ALG_ID AlgID { ALG_ID get() = 0; }

		// ������� �������� �����������
		protected: virtual HashHandle^ Construct()
		{
			// ������� �������� �����������
			return hContext->CreateHash(AlgID, nullptr, 0); 
		} 
		// ���������������� ��������
		public: virtual void Init() override;  
		// ������������ ������
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override; 
		// �������� ���-��������
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override; 
	};
}}}