#pragma once
#include "..\..\X962\X962Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace ECDSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� ECDSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BSignHash : CAPI::CNG::BSignHash
	{
		// �����������
		public: BSignHash(String^ provider) : CAPI::CNG::BSignHash(provider) {}
		 
		// ������� ��� ���������
		protected: virtual String^ GetName(IParameters^ parameters) override
		{
			// ������� ��� ���������
			return X962::Encoding::GetKeyName((ANSI::X962::IParameters^)parameters, AT_SIGNATURE); 
		}
		// ������������� ������ ����
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPrivateKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) override; 

		// ��������� ���-��������
		protected: virtual array<BYTE>^ Sign(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override
		{
			// ��������� ���-��������
			array<BYTE>^ signature = CAPI::CNG::BSignHash::Sign(
				parameters, hPrivateKey, hashAlgorithm, hash
			);
			// ������������ �������
			return X962::Encoding::DecodeSignature(
				(ANSI::X962::IParameters^)parameters, signature)->Encoded; 
		}
	};
}}}}}}}

