#pragma once
#include "PrimitiveProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// ����������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CNG::NProvider
	{
		// ��������� ��������� ������ � �������������� ���������
		private: PrimitiveProvider^ primitiveFactory; private: Dictionary<DWORD, List<String^>^>^ algs; 

		// �����������/����������
		protected: Provider(String^ name); public: virtual ~Provider(); 

		///////////////////////////////////////////////////////////////////////
		// ���������� �����������
		///////////////////////////////////////////////////////////////////////

	    // �������� ������� ����������� ������
		public: virtual KeyFactory^ GetKeyFactory(String^ keyOID) override
        {
            // �������� ������� ����������� ������
            return CAPI::Factory::GetKeyFactory(ANSI::Factory::RedirectKeyName(keyOID)); 
        }
		// ������� ����������� ��������� ������
		public:	virtual IRandFactory^ CreateRandFactory(SecurityObject^ scope, bool strong) override 
		{ 
			// ������� ����������� ��������� ������
			return RefObject::AddRef(primitiveFactory);
		}
		// ��������� ��������� ������
		public:	virtual IRand^ CreateRand(Object^ window) override 
		{ 
			// ��������� ��������� ������
			return primitiveFactory->CreateRand(window);
		}
		// ������� �������� ��������� ������
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 

		// c������ �������� ��� ����������
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			CAPI::Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, Type^ type) override; 

		///////////////////////////////////////////////////////////////////////
		// ���������� �������� � ��������/������ ������ ����������
		///////////////////////////////////////////////////////////////////////

		// ������������� ���� ������
		public: virtual CAPI::CNG::NKeyHandle^ ImportKeyPair(
			CAPI::CNG::Container^ container, IntPtr hwnd, DWORD keyType, BOOL exportable, 
			IPublicKey^ publicKey, IPrivateKey^ privateKey) override;

		// ������������� �������� ����
		public protected: virtual CAPI::CNG::NKeyHandle^ ImportPublicKey(
			DWORD keyType, IPublicKey^ publicKey) override; 

		// �������������� �������� ����
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
			ExportPublicKey(CAPI::CNG::NKeyHandle^ hPublicKey) override; 

		// �������� ������ ����
		public protected: virtual CAPI::CNG::NPrivateKey^ GetPrivateKey(
			SecurityObject^ scope, IPublicKey^ publicKey, 
			CAPI::CNG::NKeyHandle^ hKeyPair) override; 
	};
}}}}}
