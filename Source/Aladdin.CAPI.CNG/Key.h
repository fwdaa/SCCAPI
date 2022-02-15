#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	ref class NProvider; 

	///////////////////////////////////////////////////////////////////////////
	// ������ ���� �������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class NPrivateKey : CAPI::PrivateKey
	{
		// ��������� � ��������� ������� �����
		private: IParameters^ parameters; private: NKeyHandle^ hPrivateKey;

		// ����������� 
		public: NPrivateKey(NProvider^ provider, SecurityObject^ scope, 
			IPublicKey^ publicKey, NKeyHandle^ hPrivateKey
		); 
		// ����������
        public: virtual ~NPrivateKey() { CNG::Handle::Release(hPrivateKey); }

		// ��������� �����
		public: virtual property IParameters^ Parameters 
		{ 
			// ��������� �����
			IParameters^ get() override { return parameters; }  
		}
		// ��������� �����
		public protected: property NKeyHandle^ Handle 
		{ 
			// ��������� �����
			NKeyHandle^ get() { return hPrivateKey; }
		} 
        // �������������� ����
        protected: array<BYTE>^ Export(NKeyHandle^ hExportKey, String^ blobType, DWORD flags); 
	};
}}}