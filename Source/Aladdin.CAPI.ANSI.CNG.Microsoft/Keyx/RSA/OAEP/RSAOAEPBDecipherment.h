#pragma once
#include "..\PKCS1\RSAPKCS1BDecipherment.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace OAEP
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� ���������� ������ RSA (OAEP)
    ///////////////////////////////////////////////////////////////////////
	public ref class BDecipherment : RSA::PKCS1::BDecipherment
	{
		// ������������� ��������� ����������� � �����
		private: String^ hashOID; private: array<BYTE>^ label; 

		// �����������
		public: BDecipherment(String^ provider, String^ hashOID, array<BYTE>^ label) 
			
			// ��������� ���������� ���������
			: RSA::PKCS1::BDecipherment(provider) 
		{ 
			// ��������� ���������� ���������
			this->hashOID = hashOID; this->label = label;
		}
		// ������������ ������
		protected: virtual array<BYTE>^ Decrypt(
			CAPI::CNG::BKeyHandle^ hPrivateKey, array<BYTE>^ data) override; 
	};
}}}}}}}}
