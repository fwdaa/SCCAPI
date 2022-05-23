#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� ���������� ������ RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class BDecipherment : CAPI::CNG::BDecipherment
	{
		// �����������
		public: BDecipherment(String^ provider) 

			// ��������� ���������� ���������
			: CAPI::CNG::BDecipherment(provider, BCRYPT_RSA_ALGORITHM, 0) {}

		// ������������� ������ ����
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPrivateKey(
			CAPI::CNG::BProviderHandle^ hProvider, IPrivateKey^ privateKey) override; 

		// ������������ ������
		protected: virtual array<BYTE>^ Decrypt(CAPI::CNG::BKeyHandle^ hPrivateKey, array<BYTE>^ data) override
		{
			// ������������ ������
			return hPrivateKey->Decrypt(IntPtr::Zero, data, BCRYPT_PAD_PKCS1); 
		}
	};
}}}}}}}
