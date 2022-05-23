#pragma once
#include "..\PKCS1\RSAPKCS1BVerifyHash.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PSS
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA PSS
    ///////////////////////////////////////////////////////////////////////
	public ref class BVerifyHash : RSA::PKCS1::BVerifyHash
	{
		// ������������� ��������� ����������� � ������ salt-��������
		private: String^ hashOID; private: int saltLength; 

		// �����������
		public: BVerifyHash(String^ provider, String^ hashOID, 

			// ��������� ���������� ���������
			int saltLength) : RSA::PKCS1::BVerifyHash(provider) 
		{ 
			// ��������� ���������� ���������
			this->hashOID = hashOID; this->saltLength = saltLength;
		}
		// �������� �������� ������� ���-��������
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
}}}}}}}
