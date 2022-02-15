#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PSS
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA PSS
    ///////////////////////////////////////////////////////////////////////
	public ref class NSignHash : CAPI::CNG::NSignHash
	{
		// ������������� ��������� ����������� � ������ salt-��������
		private: String^ hashOID; private: int saltLength; 

		// �����������
		public: NSignHash(String^ hashOID, int saltLength)
		{
			// ��������� ���������� ���������
			this->hashOID = hashOID; this->saltLength = saltLength;
		}
		// ��������� ���-��������
		protected: virtual array<BYTE>^ Sign(SecurityObject^ scope, 
			IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPrivateKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override; 
	};
}}}}}}}}
