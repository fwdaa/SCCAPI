#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� ���������� ������ RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class NEncipherment : CAPI::CNG::NEncipherment
	{
		// �����������
		public: NEncipherment(CAPI::CNG::NProvider^ provider) 
			
			// ��������� ���������� ���������
			: CAPI::CNG::NEncipherment(provider) {}
		
		// ����������� ������
		protected: virtual array<BYTE>^ Encrypt(CAPI::CNG::NKeyHandle^ hPublicKey, array<BYTE>^ data) override
		{
			// ����������� ������
			return hPublicKey->Encrypt(IntPtr::Zero, data, BCRYPT_PAD_PKCS1); 
		}
	};
}}}}}}}
