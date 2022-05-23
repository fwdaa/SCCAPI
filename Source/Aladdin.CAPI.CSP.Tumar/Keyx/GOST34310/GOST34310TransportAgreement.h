#pragma once
#include "..\..\Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace Keyx { namespace GOST34310
{
    ///////////////////////////////////////////////////////////////////////////
    // �������� ������������ �����
    ///////////////////////////////////////////////////////////////////////////
	public ref class TransportAgreement : RefObject, ITransportAgreement
    {
		// ����������������� ���������
		private: Provider^ provider; private: DWORD flags; 

        // �����������
        public: TransportAgreement(Provider^ provider, DWORD flags) 
		{
			// ��������� ���������� ���������
			this->provider = RefObject::AddRef(provider); this->flags = flags; 
		}
		// ����������
		public: virtual ~TransportAgreement() { RefObject::Release(provider); }

	    // �������� �������-�����������
	    public: virtual TransportAgreementData^ Wrap(
			IPrivateKey^ privateKey, IPublicKey^ publicKey, 
			array<IPublicKey^>^ recipientPublicKeys, IRand^ rand, ISecretKey^ key
		);
	    // �������� �������-����������
	    public: virtual ISecretKey^ Unwrap(IPrivateKey^ recipientPrivateKey, 
			IPublicKey^ publicKey, array<BYTE>^ random, 
			array<BYTE>^ encryptedKey, SecretKeyFactory^ keyFactory
		); 
    };
}}}}}}
