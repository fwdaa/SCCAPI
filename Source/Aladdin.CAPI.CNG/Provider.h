#pragma once
#include "Handle.h"
#include "Key.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	ref class Container; 

	///////////////////////////////////////////////////////////////////////////
	// ����������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class NProvider abstract : CAPI::CryptoProvider
	{
		// ��������� � ��� ����������
		private: NProviderHandle^ hProvider; private: String^ name;

		// ������� ����������� ������ 
		private: Dictionary<String^, KeyFactory^>^ keyFactories; 

		// �����������
		protected: NProvider(String^ name);  
		// ����������
		public: virtual ~NProvider(); 

        // ��� ����������
		public:	virtual property String^ Name { String^ get() override { return name; }}

		// ��������� ����������
		public: property NProviderHandle^ Handle { NProviderHandle^ get() { return hProvider; }}

		// �������������� ������� ����������� ������
		public: virtual Dictionary<String^, KeyFactory^>^ KeyFactories() override { return keyFactories; }

		///////////////////////////////////////////////////////////////////////
		// ���������� �������� � ��������/������ ������ ����������
		///////////////////////////////////////////////////////////////////////

		// ������������� ���� ������
		public protected: virtual NKeyHandle^ ImportKeyPair(
			Container^ container, IntPtr hwnd, DWORD keyType, 
			BOOL exportable, IPublicKey^ publicKey, IPrivateKey^ privateKey
		); 
		// ������������� ���� ������
		protected: NKeyHandle^ ImportKeyPair(
			Container^ container, IntPtr hwnd, NKeyHandle^ hKey, DWORD keyType, 
			String^ typeBlob, IntPtr ptrBlob, DWORD cbBlob, 
			BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags
		); 
		// ������������� �������� ����
		public protected: virtual NKeyHandle^ ImportPublicKey(
            DWORD keyType, IPublicKey^ publicKey) = 0; 

		// �������������� �������� ����
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
            ExportPublicKey(NKeyHandle^ hPublicKey);

		// �������� ������ ����
		public protected: virtual NPrivateKey^ GetPrivateKey(
			SecurityObject^ scope, IPublicKey^ publicKey, NKeyHandle^ hKeyPair
		);
	};
}}}
