#pragma once

#include "Store.h"

using namespace System::Collections::Generic; 

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Авест
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CSP::Provider
	{
		// конструктор
		protected: Provider(IFactory^ factory, DWORD type) : CAPI::CSP::Provider(factory, type, nullptr)

			// указать хранилище контейнеров
			{ store = gcnew SCardStore(this); } private: SecurityStore^ store;

		// деструктор
		public: virtual ~Provider() { delete store; }

		// поддерживаемые типы ключей
		public: virtual Dictionary<String^, KeyUsage>^ SupportedKeys() override;

		// получить хранилище контейнера
		public: virtual array<SecurityStore^>^ GetStores(IScope^ scope) override 
		{ 
			// создать список хранилищ
			array<SecurityStore^>^ stores = gcnew array<SecurityStore^>(1); 

			// заполнить список хранилищ
			stores[0] = store; return stores; 
		}
		// получить хранилище контейнера
		public: virtual SecurityStore^ GetStore(String^ name) override { return store; }

		// идентификаторы алгоритмов
		public protected: virtual property DWORD	SignID		{ DWORD   get() = 0; } 
		public protected: virtual property DWORD	SignKeyxID	{ DWORD   get() = 0; } 
		public protected: virtual property String^	SignOID		{ String^ get() = 0; } 
		public protected: virtual property String^	KeyOID		{ String^ get() = 0; } 
		public protected: virtual property String^	ParamsOID	{ String^ get() = 0; } 
			
		// параметры ключей при генерации
		public protected: property IKeyFactory^ KeyFactory { IKeyFactory^ get() 
		{
			// вернуть фабрику ключей провайдера
			return gcnew Avest::STB11762::KeyFactory(KeyOID, ParamsOID);
		}}
		// создать ключ для алгоритма шифрования
		public: virtual CAPI::CSP::KeyHandle ConstructKey(
            CAPI::CSP::ContextHandle hContext, ALG_ID algID, IKey^ key) override; 

		// импортировать пару ключей
		public protected: virtual Aladdin::CAPI::CSP::KeyHandle ImportKeyPair(
			CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo, IPrivateKey^ privateKey) override
		{
			// импорт личных ключей не поддерживается
			throw gcnew NotSupportedException(); return CAPI::CSP::KeyHandle::Zero; 
		}
		// получить личный ключ
		public protected: virtual IPrivateKey^ GetPrivateKey(
			IKeyFactory^ keyFactory, CAPI::CSP::Container^ container, 
			CAPI::CSP::KeyHandle hKeyPair, DWORD keyType
		) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Авест Full
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderFull : Provider
	{
		// конструктор
		public: ProviderFull(IFactory^ factory) : Provider(factory, PROV_AVEST_FULL_NEW) {} 
			
		// идентификаторы алгоритмов
		public protected: virtual property DWORD SignID     { DWORD get() override { return CALG_BDS;		}} 
		public protected: virtual property DWORD SignKeyxID { DWORD get() override { return CALG_BDS_BDH; }} 

		// идентификатор алгоритма подписи
		public protected: virtual property String^ SignOID	
		{ 
			// идентификатор алгоритма подписи
			String^ get() override { return ASN1::STB::Avest::OID::bds;		}
		} 
		// идентификатор ключа
		public protected: virtual property String^ KeyOID		
		{ 
			// идентификатор ключа
			String^ get() override { return ASN1::STB::Avest::OID::bds_bdh;	}
		} 
		// идентификатор параметров
		public protected: virtual property String^ ParamsOID	
		{ 
			// идентификатор параметров
			String^ get() override { return ASN1::STB::Avest::OID::nbrb_parameters; }
		} 
		// создать алгоритм генерации ключей
		public: virtual IKeyPairGenerator^ CreateGenerator(IKeyFactory^ keyFactory) override; 

		// создать алгоритм для параметров
		public: virtual IAlgorithm^ CreateAlgorithm(
			ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) override;
	};
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Авест Pro
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderPro : Provider
	{
		// конструктор
		public: ProviderPro(IFactory^ factory) : Provider(factory, PROV_AVEST_PRO_NEW) {} 
			
		// идентификаторы алгоритмов
		public protected: virtual property DWORD SignID	  { DWORD get() override { return CALG_BDS_PRO;		}} 
		public protected: virtual property DWORD SignKeyxID { DWORD get() override { return CALG_BDS_PRO_BDH;	}} 

		// идентификатор алгоритма подписи
		public protected: virtual property String^ SignOID	
		{ 
			// идентификатор алгоритма подписи
			String^ get() override { return ASN1::STB::Avest::OID::bdspro;		}
		} 
		// идентификатор ключа
		public protected: virtual property String^ KeyOID		
		{ 
			// идентификатор ключа
			String^ get() override { return ASN1::STB::Avest::OID::bdspro_bdh;	}
		} 
		// идентификатор параметров
		public protected: virtual property String^ ParamsOID	
		{ 
			// идентификатор параметров
			String^ get() override { return ASN1::STB::Avest::OID::parameters_base;	}
		} 
		// создать алгоритм генерации ключей
		public: virtual IKeyPairGenerator^ CreateGenerator(IKeyFactory^ keyFactory) override; 

		// создать алгоритм для параметров
		public: virtual IAlgorithm^ CreateAlgorithm(
			ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) override;
	};
}}}}}

