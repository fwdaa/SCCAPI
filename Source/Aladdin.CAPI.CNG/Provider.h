#pragma once
#include "Handle.h"
#include "Key.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	ref class Container; 

	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
	public ref class NProvider abstract : CAPI::CryptoProvider
	{
		// описатель и имя провайдера
		private: NProviderHandle^ hProvider; private: String^ name;

		// фабрики кодирования ключей 
		private: Dictionary<String^, KeyFactory^>^ keyFactories; 

		// конструктор
		protected: NProvider(String^ name);  
		// деструктор
		public: virtual ~NProvider(); 

        // имя провайдера
		public:	virtual property String^ Name { String^ get() override { return name; }}

		// описатель провайдера
		public: property NProviderHandle^ Handle { NProviderHandle^ get() { return hProvider; }}

		// поддерживаемые фабрики кодирования ключей
		public: virtual Dictionary<String^, KeyFactory^>^ KeyFactories() override { return keyFactories; }

		///////////////////////////////////////////////////////////////////////
		// Выполнение операции с открытым/личным ключом контейнера
		///////////////////////////////////////////////////////////////////////

		// импортировать пару ключей
		public protected: virtual NKeyHandle^ ImportKeyPair(
			Container^ container, IntPtr hwnd, DWORD keyType, 
			BOOL exportable, IPublicKey^ publicKey, IPrivateKey^ privateKey
		); 
		// импортировать пару ключей
		protected: NKeyHandle^ ImportKeyPair(
			Container^ container, IntPtr hwnd, NKeyHandle^ hKey, DWORD keyType, 
			String^ typeBlob, IntPtr ptrBlob, DWORD cbBlob, 
			BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags
		); 
		// импортировать открытый ключ
		public protected: virtual NKeyHandle^ ImportPublicKey(
            DWORD keyType, IPublicKey^ publicKey) = 0; 

		// экспортировать открытый ключ
		public protected: virtual ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
            ExportPublicKey(NKeyHandle^ hPublicKey);

		// получить личный ключ
		public protected: virtual NPrivateKey^ GetPrivateKey(
			SecurityObject^ scope, IPublicKey^ publicKey, NKeyHandle^ hKeyPair
		);
	};
}}}
