#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	ref class Provider;

	///////////////////////////////////////////////////////////////////////////
	// ������� �������� ������ ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class SecretKeyType
	{
		// �����������
		public: SecretKeyType(ALG_ID algID)

			// ��������� ���������� ���������
			{ this->algID = algID; } private: ALG_ID algID; 

		// ������������� ���������
		public: property ALG_ID AlgID { ALG_ID get() { return algID; }}

		// ������� ���� ��� ��������� ����������
		public: virtual KeyHandle^ ConstructKey(
			ContextHandle^ hContext, array<BYTE>^ value, DWORD flags
		); 
		// �������� �������� �����
		public: virtual array<BYTE>^ GetKeyValue(
			ContextHandle^ hContext, KeyHandle^ hKey
		); 
	};
	///////////////////////////////////////////////////////////////////////////
	// ���� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class SecretKey : RefObject, ISecretKey
	{
        // ���������, ��� � ��������� �����
		private: CSP::Provider^ provider; private: SecretKeyFactory^ keyFactory; private: KeyHandle^ hKey; 

		// ����������� 
		public: SecretKey(CSP::Provider^ provider, SecretKeyFactory^ keyFactory, KeyHandle^ hKey);
		// ����������
		public: virtual ~SecretKey(); private: array<BYTE>^ value; 

        // ��������� �����
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }} 
		// ��������� �����
		public: property KeyHandle^ Handle { KeyHandle^ get() { return hKey; }} 

		// ��� �����
		public: virtual property SecretKeyFactory^ KeyFactory { SecretKeyFactory^ get() { return keyFactory; }}
        // ������ �����
        public: virtual property int Length { int get(); }
        // �������� �����
		public: virtual property array<BYTE>^ Value { array<BYTE>^ get(); }
	};
	///////////////////////////////////////////////////////////////////////////
	// ������ ���� �������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::PrivateKey
	{
		// ��������� � ������������� �����
		private: IParameters^ parameters; array<BYTE>^ keyID;  
		// ��������� ����� � ��� �����
		private: KeyHandle^	hPrivateKey; DWORD keyType; 

		// ����������� 
		public protected: PrivateKey(Provider^ provider, SecurityObject^ scope, 
			IPublicKey^ publicKey, KeyHandle^ hPrivateKey, array<BYTE>^ keyID, DWORD keyType
		);  
		// ����������
        public: virtual ~PrivateKey() { Handle::Release(hPrivateKey); } 

		// ��������� �����
		public: virtual property IParameters^ Parameters 
		{ 
			// ��������� �����
			IParameters^ get() override { return parameters; }  
		}
		// �������� ��������� �����
		public: KeyHandle^ OpenHandle(); 

		// ������������� �����
		public: property array<BYTE>^ KeyID { array<BYTE>^ get() { return keyID; }}
		// ��� �����
		public: property DWORD KeyType { DWORD get() { return keyType; }}

        // �������������� ����
        protected: array<BYTE>^ Export(KeyHandle^ hExportKey, DWORD flags); 
	};
}}}
