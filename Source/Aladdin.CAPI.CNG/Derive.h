#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм согласования общего ключа
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyAgreement abstract : CAPI::KeyAgreement
	{
		private: String^ provider;	// имя провайдера

		// конструктор
		protected: BKeyAgreement(String^ provider) { this->provider = provider; }

	    // согласовать общий ключ на стороне получателя
		public: virtual ISecretKey^ DeriveKey(IPrivateKey^ privateKey, 
			IPublicKey^ publicKey, array<BYTE>^ random, 
			SecretKeyFactory^ keyFactory, int keySize) override; 

		// имя алгоритма
		protected: virtual String^ GetName(IParameters^ parameters) = 0; 

		// импортировать личный ключ
		protected: virtual BKeyHandle^ ImportPrivateKey(
			BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) = 0; 

		// импортировать открытый ключ
		protected: virtual BKeyHandle^ ImportPublicKey(
			BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) = 0; 

	    // согласовать общий ключ на стороне получателя
		protected: virtual array<BYTE>^ DeriveKey(IParameters^ parameters, 
			BSecretHandle^ hSecret, array<BYTE>^ random, int keySize) = 0; 

		// выполнить согласование общего ключа
		protected: virtual BSecretHandle^ AgreementSecret(
			BKeyHandle^ hPrivateKey, BKeyHandle^ hPublicKey)
		{
			// выполнить согласование общего ключа
			return hPrivateKey->AgreementSecret(hPublicKey, 0); 
		}
	};
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм согласования общего ключа
	///////////////////////////////////////////////////////////////////////////
	public ref class NKeyAgreement abstract : CAPI::KeyAgreement
	{
	    // согласовать общий ключ на стороне получателя
		public: virtual ISecretKey^ DeriveKey(IPrivateKey^ privateKey, 
			IPublicKey^ publicKey, array<BYTE>^ random, 
			SecretKeyFactory^ keyFactory, int keySize) override; 

		// выполнить согласование общего ключа
		protected: NSecretHandle^ AgreementSecret(SecurityObject^ scope, 
			NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey, DWORD flags
		); 
		// выполнить согласование общего ключа
		protected: virtual NSecretHandle^ AgreementSecret(
			SecurityObject^ scope, NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey)
		{
			// выполнить согласование общего ключа
			return AgreementSecret(scope, hPrivateKey, hPublicKey, 0); 
		}
	    // согласовать общий ключ на стороне получателя
		protected: virtual array<BYTE>^ DeriveKey(IParameters^ parameters, 
			NSecretHandle^ hSecret, array<BYTE>^ random, int keySize) = 0; 
	};
}}}