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

	    // �������������� ������� ����������� ������
		public: virtual array<KeyFactory^>^ KeyFactories() override; 

		///////////////////////////////////////////////////////////////////////
		// ���������� �����������
		///////////////////////////////////////////////////////////////////////

		// �������� ��������� �� ���������
		public: virtual CAPI::Culture^ GetCulture(SecurityStore^ scope, String^ keyOID) override
        {
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// �������� ��������� �� ���������
			return factory.Get()->GetCulture(scope, keyOID); 
		}
		// �������� ��������� �� ���������
		public: virtual PBE::PBECulture^ GetCulture(PBE::PBEParameters^ parameters, String^ keyOID) override
        {
			// ������� ������� ����������
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// �������� ��������� �� ���������
			return factory.Get()->GetCulture(parameters, keyOID); 
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
			CAPI::Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type) override; 

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
