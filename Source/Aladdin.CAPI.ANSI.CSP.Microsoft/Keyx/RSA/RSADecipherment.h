#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Keyx { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� ���������� ������ RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class Decipherment : CAPI::CSP::Decipherment
	{
		// �����������
		public: Decipherment(CAPI::CSP::Provider^ provider, DWORD flags) 

			// ��������� ���������� ���������
			: CAPI::CSP::Decipherment(provider, flags) {} 

		// ������������ ������
		public: virtual array<BYTE>^ Decrypt(IPrivateKey^ privateKey, array<BYTE>^ data) override
		{
			// ������� ����� ������ � �������� ������� ������ 
			data = (array<BYTE>^)data->Clone(); Array::Reverse(data);

			// ������������ ������
			return CAPI::CSP::Decipherment::Decrypt(privateKey, data); 
		}
	};
}}}}}}}
