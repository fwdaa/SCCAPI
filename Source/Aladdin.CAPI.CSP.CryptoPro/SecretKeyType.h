#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ��� ����� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class SecretKeyType : CAPI::CSP::SecretKeyType
	{
		// �����������
		public: SecretKeyType(ALG_ID algID) : CAPI::CSP::SecretKeyType(algID) {}

		// ������� ���� ��� ��������� ����������
		public: virtual CAPI::CSP::KeyHandle^ ConstructKey(
			CAPI::CSP::ContextHandle^ hContext, array<BYTE>^ value, DWORD flags) override; 

		// �������� �������� �����
		public: virtual array<BYTE>^ GetKeyValue(
			CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) override; 
	};
}}}}
