#pragma once
#include "..\..\X957\X957Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace DSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� DSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BSignHash : CAPI::CNG::BSignHash
	{
		// �����������
		public: BSignHash(String^ provider) : CAPI::CNG::BSignHash(provider) {}
		 
		// ������� ��� ���������
		protected: virtual String^ GetName(IParameters^ parameters) override { return BCRYPT_DSA_ALGORITHM; }

		// ������������� ������ ����
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPrivateKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) override; 

		// ��������� ���-��������
		protected: virtual array<BYTE>^ Sign(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override
		{
			// ��������� ���-��������
			array<BYTE>^ signature = CAPI::CNG::BSignHash::Sign(parameters, hPrivateKey, hashAlgorithm, hash);

			// ������������ �������
			return X957::Encoding::DecodeSignature((ANSI::X957::IParameters^)parameters, signature)->Encoded; 
		}
	};
}}}}}}}
