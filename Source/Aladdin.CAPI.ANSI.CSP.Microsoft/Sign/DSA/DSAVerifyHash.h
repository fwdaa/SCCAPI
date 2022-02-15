#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Sign { namespace DSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения DH
    ///////////////////////////////////////////////////////////////////////
    public ref class VerifyHash : CAPI::CSP::VerifyHash
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// конструктор
		public: VerifyHash(CAPI::CSP::Provider^ provider) : CAPI::CSP::VerifyHash(provider, 0) {} 

		// создать алгоритм хэширования
		protected: virtual CAPI::CSP::HashHandle^ CreateHash(
			CAPI::CSP::ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm) override;

		// проверить подпись хэш-значения
		public: virtual void Verify(IPublicKey^ publicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
			array<BYTE>^ hash, array<BYTE>^ signature) override;
	};
}}}}}}}
