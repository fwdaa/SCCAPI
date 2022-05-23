#pragma once
#include "..\..\X957\X957Encoding.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace DSA
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� DSA
    ///////////////////////////////////////////////////////////////////////
	public ref class NSignHash : CAPI::CNG::NSignHash 
	{
		// ��������� ���-��������
		protected: virtual array<BYTE>^ Sign(SecurityObject^ scope, 
			IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPrivateKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override
		{
			// ��������� ���-��������
			array<BYTE>^ signature = CAPI::CNG::NSignHash::Sign(
				scope, parameters, hPrivateKey, hashAlgorithm, hash
			);
			// ������������ �������
			return X957::Encoding::DecodeSignature(
				(ANSI::X957::IParameters^)parameters, signature)->Encoded; 
		}
	};
}}}}}}

