#pragma once
#include "..\..\X957\X957Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace DSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� DSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BVerifyHash : CAPI::CNG::BVerifyHash 
	{
		// �����������
		public: BVerifyHash(String^ provider) : CAPI::CNG::BVerifyHash(provider) {}
		 
		// ������� ��� ���������
		protected: virtual String^ GetName(IParameters^ parameters) override { return BCRYPT_DSA_ALGORITHM; }

		// ������������� �������� ����
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPublicKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) override; 

		// �������� �������� ������� ���-��������
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override
		{
			// ������������� �������� �������
			ASN1::ANSI::X957::DssSigValue^ encoded = 
				gcnew ASN1::ANSI::X957::DssSigValue(ASN1::Encodable::Decode(signature)); 

			// ������������ �������
			signature = X957::Encoding::EncodeSignature((ANSI::X957::IParameters^)parameters, encoded); 

			// ��������� ������� ���-��������
			CAPI::CNG::BVerifyHash::Verify(parameters, hPublicKey, hashAlgorithm, hash, signature); 
		}
	};
}}}}}}}
