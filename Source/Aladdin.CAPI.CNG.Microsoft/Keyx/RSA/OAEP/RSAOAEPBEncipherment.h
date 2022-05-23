#pragma once
#include "..\PKCS1\RSAPKCS1BEncipherment.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace OAEP
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� ���������� ������ RSA (OAEP)
    ///////////////////////////////////////////////////////////////////////
	public ref class BEncipherment : RSA::PKCS1::BEncipherment
	{
		// ������������� ��������� ����������� � �����
		private: String^ hashOID; private: array<BYTE>^ label; 

		// �����������
		public: BEncipherment(String^ provider, 
			String^ hashOID, array<BYTE>^ label) : RSA::PKCS1::BEncipherment(provider) 
		{ 
			// ��������� ���������� ���������
			this->hashOID = hashOID; this->label = label;
		} 
		// ����������� ������
		protected: virtual array<BYTE>^ Encrypt(
			CAPI::CNG::BKeyHandle^ hPublicKey, array<BYTE>^ data) override; 
	};
}}}}}}}
