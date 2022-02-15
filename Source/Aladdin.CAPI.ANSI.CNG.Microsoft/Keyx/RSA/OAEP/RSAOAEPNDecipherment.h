#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace OAEP
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� ���������� ������ OAEP
    ///////////////////////////////////////////////////////////////////////
	public ref class NDecipherment : CAPI::CNG::NDecipherment
	{
		// ������������� ��������� ����������� � �����
		private: String^ hashOID; private: array<BYTE>^ label; 

		// �����������
		public: NDecipherment(String^ hashOID, array<BYTE>^ label) 
		{
			// ��������� ���������� ���������
			this->hashOID = hashOID; this->label = label;
		}
		// ������������ ������
		protected: virtual array<BYTE>^ Decrypt(SecurityObject^ scope, 
			CAPI::CNG::NKeyHandle^ hPrivateKey, array<BYTE>^ data) override; 
	};
}}}}}}}}
