#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PSS
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA PSS
    ///////////////////////////////////////////////////////////////////////
	public ref class NVerifyHash : CAPI::CNG::NVerifyHash
	{
		// ������������� ��������� ����������� � ������ salt-��������
		private: String^ hashOID; private: int saltLength; 

		// �����������
		public: NVerifyHash(CAPI::CNG::NProvider^ provider, 
			String^ hashOID, int saltLength) : CAPI::CNG::NVerifyHash(provider)
		{
			// ��������� ���������� ���������
			this->hashOID = hashOID; this->saltLength = saltLength;
		}
		// �������� �������� ������� ���-��������
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
}}}}}}}
