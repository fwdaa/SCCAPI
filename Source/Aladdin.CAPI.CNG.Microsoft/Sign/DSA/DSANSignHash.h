#pragma once
#include "..\..\X957\X957Encoding.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace DSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения DSA
    ///////////////////////////////////////////////////////////////////////
	public ref class NSignHash : CAPI::CNG::NSignHash 
	{
		// подписать хэш-значение
		protected: virtual array<BYTE>^ Sign(SecurityObject^ scope, 
			IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPrivateKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override
		{
			// подписать хэш-значение
			array<BYTE>^ signature = CAPI::CNG::NSignHash::Sign(
				scope, parameters, hPrivateKey, hashAlgorithm, hash
			);
			// закодировать подпись
			return X957::Encoding::DecodeSignature(
				(ANSI::X957::IParameters^)parameters, signature)->Encoded; 
		}
	};
}}}}}}

