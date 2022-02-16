#pragma once
#include "PrimitiveProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CNG::NProvider
	{
		// генератор случайных данных и поддерживаемые алгоритмы
		private: PrimitiveProvider^ primitiveFactory; private: Dictionary<DWORD, List<String^>^>^ algs; 

		// конструктор/деструктор
		protected: Provider(String^ name); public: virtual ~Provider(); 

	    // поддерживаемые фабрики кодирования ключей
		public: virtual array<KeyFactory^>^ KeyFactories() override; 

		///////////////////////////////////////////////////////////////////////
		// Управление алгоритмами
		///////////////////////////////////////////////////////////////////////

		// получить алгоритмы по умолчанию
		public: virtual CAPI::Culture^ GetCulture(SecurityStore^ scope, String^ keyOID) override
        {
			// указать фабрику алгоритмов
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// получить алгоритмы по умолчанию
			return factory.Get()->GetCulture(scope, keyOID); 
		}
		// получить алгоритмы по умолчанию
		public: virtual PBE::PBECulture^ GetCulture(PBE::PBEParameters^ parameters, String^ keyOID) override
        {
			// указать фабрику алгоритмов
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// получить алгоритмы по умолчанию
			return factory.Get()->GetCulture(parameters, keyOID); 
		}
		// фабрика генераторов случайных данных
		public:	virtual IRandFactory^ CreateRandFactory(SecurityObject^ scope, bool strong) override 
		{ 
			// фабрика генераторов случайных данных
			return RefObject::AddRef(primitiveFactory);
		}
		// генератор случайных данных
		public:	virtual IRand^ CreateRand(Object^ window) override 
		{ 
			// генератор случайных данных
			return primitiveFactory->CreateRand(window);
		}
		// создать алгоритм генерации ключей
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 

		// cоздать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			CAPI::Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type) override; 

		///////////////////////////////////////////////////////////////////////
		// Выполнение операции с открытым/личным ключом контейнера
		///////////////////////////////////////////////////////////////////////

		// импортировать пару ключей
		public: virtual CAPI::CNG::NKeyHandle^ ImportKeyPair(
			CAPI::CNG::Container^ container, IntPtr hwnd, DWORD keyType, BOOL exportable, 
			IPublicKey^ publicKey, IPrivateKey^ privateKey) override;

		// импортировать открытый ключ
		public protected: virtual CAPI::CNG::NKeyHandle^ ImportPublicKey(
			DWORD keyType, IPublicKey^ publicKey) override; 

		// экспортировать открытый ключ
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
			ExportPublicKey(CAPI::CNG::NKeyHandle^ hPublicKey) override; 

		// получить личный ключ
		public protected: virtual CAPI::CNG::NPrivateKey^ GetPrivateKey(
			SecurityObject^ scope, IPublicKey^ publicKey, 
			CAPI::CNG::NKeyHandle^ hKeyPair) override; 
	};
}}}}}
