#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� ���������� ������ RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class BEncipherment : CAPI::CNG::BEncipherment
	{
		// �����������
		public: BEncipherment(String^ provider) 

			// ��������� ���������� ���������
			: CAPI::CNG::BEncipherment(provider, BCRYPT_RSA_ALGORITHM, 0) {}

		// ������������� �������� ����
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPublicKey(
			CAPI::CNG::BProviderHandle^ hProvider, IPublicKey^ publicKey) override; 

		// ����������� ������
		protected: virtual array<BYTE>^ Encrypt(CAPI::CNG::BKeyHandle^ hPublicKey, array<BYTE>^ data) override
		{
			// ����������� ������
			return hPublicKey->Encrypt(IntPtr::Zero, data, BCRYPT_PAD_PKCS1); 
		}
	};
}}}}}}}
