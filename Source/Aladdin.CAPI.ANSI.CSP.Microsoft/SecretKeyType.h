#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// ��� ����� RC2
	///////////////////////////////////////////////////////////////////////////
	public ref class SecretKeyType : CAPI::CSP::SecretKeyType
	{
		// �����������
		public: SecretKeyType(ALG_ID algID) : CAPI::CSP::SecretKeyType(algID) {}

		// ������� ���� ��� ��������� ����������
		public: virtual CAPI::CSP::KeyHandle^ ConstructKey(
			CAPI::CSP::ContextHandle^ hContext, array<BYTE>^ value, DWORD flags) override
		{
			// ������� ������� ���������� salt-��������
			if (value->Length == 5) flags |= CRYPT_NO_SALT;

			// ������� ������� ����������� �������
			if (AlgID == CALG_RC2) flags |= CRYPT_IPSEC_HMAC_KEY; 

			// ������� ������� �������
			return CAPI::CSP::SecretKeyType::ConstructKey(hContext, value, flags);
		}
	};
}}}}}
