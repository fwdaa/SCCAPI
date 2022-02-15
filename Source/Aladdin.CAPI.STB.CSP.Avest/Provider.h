#pragma once

#include "Store.h"

using namespace System::Collections::Generic; 

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������������� �����
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CSP::Provider
	{
		// �����������
		protected: Provider(IFactory^ factory, DWORD type) : CAPI::CSP::Provider(factory, type, nullptr)

			// ������� ��������� �����������
			{ store = gcnew SCardStore(this); } private: SecurityStore^ store;

		// ����������
		public: virtual ~Provider() { delete store; }

		// �������������� ���� ������
		public: virtual Dictionary<String^, KeyUsage>^ SupportedKeys() override;

		// �������� ��������� ����������
		public: virtual array<SecurityStore^>^ GetStores(IScope^ scope) override 
		{ 
			// ������� ������ ��������
			array<SecurityStore^>^ stores = gcnew array<SecurityStore^>(1); 

			// ��������� ������ ��������
			stores[0] = store; return stores; 
		}
		// �������� ��������� ����������
		public: virtual SecurityStore^ GetStore(String^ name) override { return store; }

		// �������������� ����������
		public protected: virtual property DWORD	SignID		{ DWORD   get() = 0; } 
		public protected: virtual property DWORD	SignKeyxID	{ DWORD   get() = 0; } 
		public protected: virtual property String^	SignOID		{ String^ get() = 0; } 
		public protected: virtual property String^	KeyOID		{ String^ get() = 0; } 
		public protected: virtual property String^	ParamsOID	{ String^ get() = 0; } 
			
		// ��������� ������ ��� ���������
		public protected: property IKeyFactory^ KeyFactory { IKeyFactory^ get() 
		{
			// ������� ������� ������ ����������
			return gcnew Avest::STB11762::KeyFactory(KeyOID, ParamsOID);
		}}
		// ������� ���� ��� ��������� ����������
		public: virtual CAPI::CSP::KeyHandle ConstructKey(
            CAPI::CSP::ContextHandle hContext, ALG_ID algID, IKey^ key) override; 

		// ������������� ���� ������
		public protected: virtual Aladdin::CAPI::CSP::KeyHandle ImportKeyPair(
			CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo, IPrivateKey^ privateKey) override
		{
			// ������ ������ ������ �� ��������������
			throw gcnew NotSupportedException(); return CAPI::CSP::KeyHandle::Zero; 
		}
		// �������� ������ ����
		public protected: virtual IPrivateKey^ GetPrivateKey(
			IKeyFactory^ keyFactory, CAPI::CSP::Container^ container, 
			CAPI::CSP::KeyHandle hKeyPair, DWORD keyType
		) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������������� ����� Full
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderFull : Provider
	{
		// �����������
		public: ProviderFull(IFactory^ factory) : Provider(factory, PROV_AVEST_FULL_NEW) {} 
			
		// �������������� ����������
		public protected: virtual property DWORD SignID     { DWORD get() override { return CALG_BDS;		}} 
		public protected: virtual property DWORD SignKeyxID { DWORD get() override { return CALG_BDS_BDH; }} 

		// ������������� ��������� �������
		public protected: virtual property String^ SignOID	
		{ 
			// ������������� ��������� �������
			String^ get() override { return ASN1::STB::Avest::OID::bds;		}
		} 
		// ������������� �����
		public protected: virtual property String^ KeyOID		
		{ 
			// ������������� �����
			String^ get() override { return ASN1::STB::Avest::OID::bds_bdh;	}
		} 
		// ������������� ����������
		public protected: virtual property String^ ParamsOID	
		{ 
			// ������������� ����������
			String^ get() override { return ASN1::STB::Avest::OID::nbrb_parameters; }
		} 
		// ������� �������� ��������� ������
		public: virtual IKeyPairGenerator^ CreateGenerator(IKeyFactory^ keyFactory) override; 

		// ������� �������� ��� ����������
		public: virtual IAlgorithm^ CreateAlgorithm(
			ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������������� ����� Pro
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderPro : Provider
	{
		// �����������
		public: ProviderPro(IFactory^ factory) : Provider(factory, PROV_AVEST_PRO_NEW) {} 
			
		// �������������� ����������
		public protected: virtual property DWORD SignID	  { DWORD get() override { return CALG_BDS_PRO;		}} 
		public protected: virtual property DWORD SignKeyxID { DWORD get() override { return CALG_BDS_PRO_BDH;	}} 

		// ������������� ��������� �������
		public protected: virtual property String^ SignOID	
		{ 
			// ������������� ��������� �������
			String^ get() override { return ASN1::STB::Avest::OID::bdspro;		}
		} 
		// ������������� �����
		public protected: virtual property String^ KeyOID		
		{ 
			// ������������� �����
			String^ get() override { return ASN1::STB::Avest::OID::bdspro_bdh;	}
		} 
		// ������������� ����������
		public protected: virtual property String^ ParamsOID	
		{ 
			// ������������� ����������
			String^ get() override { return ASN1::STB::Avest::OID::parameters_base;	}
		} 
		// ������� �������� ��������� ������
		public: virtual IKeyPairGenerator^ CreateGenerator(IKeyFactory^ keyFactory) override; 

		// ������� �������� ��� ����������
		public: virtual IAlgorithm^ CreateAlgorithm(
			ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) override;
	};
}}}}}

