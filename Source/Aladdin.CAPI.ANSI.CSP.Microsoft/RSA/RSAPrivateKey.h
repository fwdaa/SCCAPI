#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ RSA
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::ANSI::RSA::IPrivateKey
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		private: Math::BigInteger^ modulus;         // параметр N	
		private: Math::BigInteger^ publicExponent;  // параметр E
		private: Math::BigInteger^ privateExponent; // параметр D
		private: Math::BigInteger^ prime1;          // параметр P
		private: Math::BigInteger^ prime2;          // параметр Q
		private: Math::BigInteger^ exponent1;       // параметр D (mod P-1)
		private: Math::BigInteger^ exponent2;       // параметр D (mod Q-1)
		private: Math::BigInteger^ coefficient;     // параметр Q^{-1}(mod P)

		// конструктор
		public: PrivateKey(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, ANSI::RSA::IPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID, DWORD keyType)

			// сохранить переданные параметры
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, keyType) {} 

		public: virtual property Math::BigInteger^ Modulus { Math::BigInteger^ get()
        {
			// вернуть значение параметра
			if (modulus == nullptr) GetPrivateValue(); return modulus; 
        }} 
		public: virtual property Math::BigInteger^ PublicExponent { Math::BigInteger^ get()
        {
			// вернуть значение параметра
			if (publicExponent == nullptr) GetPrivateValue(); return publicExponent; 
        }} 
		public: virtual property Math::BigInteger^ PrivateExponent { Math::BigInteger^ get()
        {
			// вернуть значение параметра
			if (privateExponent == nullptr) GetPrivateValue(); return privateExponent; 
        }} 
		public: virtual property Math::BigInteger^ PrimeP { Math::BigInteger^ get()			
        {
			// вернуть значение параметра
			if (prime1 == nullptr) GetPrivateValue(); return prime1; 
        }} 
		public: virtual property Math::BigInteger^ PrimeQ { Math::BigInteger^ get()			
        {
			// вернуть значение параметра
			if (prime2 == nullptr) GetPrivateValue(); return prime2; 
        }} 
		public: virtual property Math::BigInteger^ PrimeExponentP { Math::BigInteger^ get()		
        {
			// вернуть значение параметра
			if (exponent1 == nullptr) GetPrivateValue(); return exponent1; 
        }} 
		public: virtual property Math::BigInteger^ PrimeExponentQ { Math::BigInteger^ get()		
        {
			// вернуть значение параметра
			if (exponent2 == nullptr) GetPrivateValue(); return exponent2; 
        }} 
		public: virtual property Math::BigInteger^ CrtCoefficient { Math::BigInteger^ get()		
        {
			// вернуть значение параметра
			if (coefficient == nullptr) GetPrivateValue(); return coefficient; 
        }} 
		// определить секретное значение
		private: void GetPrivateValue(); 
	};
}}}}}}