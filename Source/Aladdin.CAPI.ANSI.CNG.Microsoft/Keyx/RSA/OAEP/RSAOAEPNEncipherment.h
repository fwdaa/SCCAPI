#pragma once
#include "..\PKCS1\RSAPKCS1NEncipherment.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace OAEP
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� ���������� ������ OAEP
    ///////////////////////////////////////////////////////////////////////
	public ref class NEncipherment : RSA::PKCS1::NEncipherment
	{
		// ������������� ��������� ����������� � �����
		private: String^ hashOID; private: int hashSize; private: array<BYTE>^ label; 

		// �����������
		public: NEncipherment(CAPI::CNG::NProvider^ provider, String^ hashOID, array<BYTE>^ label);  

		// ����������� ������
		protected: virtual array<BYTE>^ Encrypt(
			CAPI::CNG::NKeyHandle^ hPublicKey, array<BYTE>^ data) override;
	};
}}}}}}}}
