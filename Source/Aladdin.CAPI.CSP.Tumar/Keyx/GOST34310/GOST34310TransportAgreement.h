#pragma once
#include "..\..\Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace Keyx { namespace GOST34310
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм согласования ключа
    ///////////////////////////////////////////////////////////////////////////
	public ref class TransportAgreement : RefObject, ITransportAgreement
    {
		// криптографический провайдер
		private: Provider^ provider; private: DWORD flags; 

        // конструктор
        public: TransportAgreement(Provider^ provider, DWORD flags) 
		{
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); this->flags = flags; 
		}
		// деструктор
		public: virtual ~TransportAgreement() { RefObject::Release(provider); }

	    // действия стороны-отправителя
	    public: virtual TransportAgreementData^ Wrap(
			IPrivateKey^ privateKey, IPublicKey^ publicKey, 
			array<IPublicKey^>^ recipientPublicKeys, IRand^ rand, ISecretKey^ key
		);
	    // действия стороны-получателя
	    public: virtual ISecretKey^ Unwrap(IPrivateKey^ recipientPrivateKey, 
			IPublicKey^ publicKey, array<BYTE>^ random, 
			array<BYTE>^ encryptedKey, SecretKeyFactory^ keyFactory
		); 
    };
}}}}}}
