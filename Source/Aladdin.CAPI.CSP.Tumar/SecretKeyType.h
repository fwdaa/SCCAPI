#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar
{
	///////////////////////////////////////////////////////////////////////////
	// ��� ����� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class SecretKeyType : Microsoft::SecretKeyType
	{
		// �����������
		public: SecretKeyType(ALG_ID algID) : Microsoft::SecretKeyType(algID) {}

		// ������� ���� ��� ��������� ����������
		public: virtual CAPI::CSP::KeyHandle^ ConstructKey(
			CAPI::CSP::ContextHandle^ hContext, array<BYTE>^ value, DWORD flags) override; 

		// �������� �������� �����
		public: virtual array<BYTE>^ GetKeyValue(
			CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) override; 
	};
}}}}
