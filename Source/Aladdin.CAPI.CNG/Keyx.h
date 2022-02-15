#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////
	public ref class BEncipherment abstract : CAPI::Encipherment
	{	
		// описатель контекста
		private: Using<BProviderHandle^> hProvider; 

		// конструктор
		protected: BEncipherment(String^ provider, String^ name, DWORD flags)

			// сохранить описатель провайдера алгоритма
			: hProvider(gcnew BProviderHandle(provider, name, flags)) {} 

		// импортировать открытый ключ
		protected: virtual BKeyHandle^ ImportPublicKey(
			BProviderHandle^ hProvider, IPublicKey^ publicKey) = 0; 

		// зашифровать данные
		protected: virtual array<BYTE>^ Encrypt(BKeyHandle^ hPublicKey, array<BYTE>^ data)
		{
			// зашифровать данные
			return hPublicKey->Encrypt(IntPtr::Zero, data, 0); 
		}
		// зашифровать данные
		public: virtual array<BYTE>^ Encrypt(
			IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data) override; 
	};
	public ref class BDecipherment abstract : CAPI::Decipherment
	{	
		// описатель контекста
		private: Using<BProviderHandle^> hProvider; 

		// конструктор
		protected: BDecipherment(String^ provider, String^ name, DWORD flags)

			// сохранить описатель провайдера алгоритма
			: hProvider(gcnew BProviderHandle(provider, name, flags)) {} 

		// импортировать личный ключ
		protected: virtual BKeyHandle^ ImportPrivateKey(
			BProviderHandle^ hProvider, IPrivateKey^ privateKey) = 0; 

		// расшифровать данные
		protected: virtual array<BYTE>^ Decrypt(BKeyHandle^ hPrivateKey, array<BYTE>^ data)
		{
			// расшифровать данные
			return hPrivateKey->Decrypt(IntPtr::Zero, data, 0); 
		}
		// расшифровать данные
		public: virtual array<BYTE>^ Decrypt(IPrivateKey^ privateKey, array<BYTE>^ data) override; 
	};
	public ref class NEncipherment abstract : CAPI::Encipherment
	{
		// конструктор
		protected: NEncipherment(NProvider^ provider) 
		
			// сохранить переданные параметры
			{ this->provider = RefObject::AddRef(provider); } private: NProvider^ provider; 

		// деструктор
		public: virtual ~NEncipherment() { RefObject::Release(provider); }

		// используемый провайдер
		public: property NProvider^ Provider { NProvider^ get() { return provider; }}

		// зашифровать данные
		protected: virtual array<BYTE>^ Encrypt(NKeyHandle^ hPublicKey, array<BYTE>^ data)
		{
			// зашифровать данные
			return hPublicKey->Encrypt(IntPtr::Zero, data, 0); 
		}
		// зашифровать данные
		public: virtual array<BYTE>^ Encrypt(IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data) override; 
	};
	public ref class NDecipherment abstract : CAPI::Decipherment
	{
		// расшифровать данные
		protected: array<BYTE>^ Decrypt(SecurityObject^ scope, 
			NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ data, DWORD flags
		);
		// расшифровать данные
		protected: virtual array<BYTE>^ Decrypt(
			SecurityObject^ scope, NKeyHandle^ hPrivateKey, array<BYTE>^ data)
		{
			// расшифровать данные
			return Decrypt(scope, hPrivateKey, IntPtr::Zero, data, 0); 
		}
		// расшифровать данные
		public: virtual array<BYTE>^ Decrypt(IPrivateKey^ privateKey, array<BYTE>^ data) override; 
	};
}}}
