#pragma once
#include "..\..\X962\X962Encoding.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace ECDSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� ECDSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BVerifyHash : CAPI::CNG::BVerifyHash 
	{
		// �����������
		public: BVerifyHash(String^ provider) : CAPI::CNG::BVerifyHash(provider) {}
		 
		// ������� ��� ���������
		protected: virtual String^ GetName(IParameters^ parameters) override
		{
			// ������� ��� ���������
			return X962::Encoding::GetKeyName((ANSI::X962::IParameters^)parameters, AT_SIGNATURE); 
		}
		// ������������� �������� ����
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPublicKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) override; 

		// �������� �������� ������� ���-��������
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override
		{
			// ������������� �������� �������
			ASN1::ANSI::X962::ECDSASigValue^ encoded = 
				gcnew ASN1::ANSI::X962::ECDSASigValue(ASN1::Encodable::Decode(signature)); 

			// ������������ �������
			signature = X962::Encoding::EncodeSignature((ANSI::X962::IParameters^)parameters, encoded); 

			// ��������� ������� ���-��������
			CAPI::CNG::BVerifyHash::Verify(parameters, hPublicKey, hashAlgorithm, hash, signature); 
		}
	};
}}}}}}
