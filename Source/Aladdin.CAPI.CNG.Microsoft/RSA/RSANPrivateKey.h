#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace RSA
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ���� RSA
	///////////////////////////////////////////////////////////////////////////
	public ref class NPrivateKey : CAPI::CNG::NPrivateKey, CAPI::ANSI::RSA::IPrivateKey
	{
		private: Math::BigInteger^ modulus;         // �������� N	
		private: Math::BigInteger^ publicExponent;  // �������� E
		private: Math::BigInteger^ privateExponent; // �������� D
		private: Math::BigInteger^ prime1;          // �������� P
		private: Math::BigInteger^ prime2;          // �������� Q
		private: Math::BigInteger^ exponent1;       // �������� D (mod P-1)
		private: Math::BigInteger^ exponent2;       // �������� D (mod Q-1)
		private: Math::BigInteger^ coefficient;     // �������� Q^{-1}(mod P)

		// �����������
		public: NPrivateKey(CAPI::CNG::NProvider^ provider, SecurityObject^ scope, 
			ANSI::RSA::IPublicKey^ publicKey, CAPI::CNG::NKeyHandle^ hPrivateKey)
			: CAPI::CNG::NPrivateKey(provider, scope, publicKey, hPrivateKey) {} 

		public: virtual property Math::BigInteger^ Modulus { Math::BigInteger^ get()
        {
			// ������� �������� ���������
			if (modulus == nullptr) GetPrivateValue(); return modulus; 
        }} 
		public: virtual property Math::BigInteger^ PublicExponent { Math::BigInteger^ get()
        {
			// ������� �������� ���������
			if (publicExponent == nullptr) GetPrivateValue(); return publicExponent; 
        }} 
		public: virtual property Math::BigInteger^ PrivateExponent { Math::BigInteger^ get()
        {
			// ������� �������� ���������
			if (privateExponent == nullptr) GetPrivateValue(); return privateExponent; 
        }} 
		public: virtual property Math::BigInteger^ PrimeP { Math::BigInteger^ get()			
        {
			// ������� �������� ���������
			if (prime1 == nullptr) GetPrivateValue(); return prime1; 
        }} 
		public: virtual property Math::BigInteger^ PrimeQ { Math::BigInteger^ get()			
        {
			// ������� �������� ���������
			if (prime2 == nullptr) GetPrivateValue(); return prime2; 
        }} 
		public: virtual property Math::BigInteger^ PrimeExponentP { Math::BigInteger^ get()		
        {
			// ������� �������� ���������
			if (exponent1 == nullptr) GetPrivateValue(); return exponent1; 
        }} 
		public: virtual property Math::BigInteger^ PrimeExponentQ { Math::BigInteger^ get()		
        {
			// ������� �������� ���������
			if (exponent2 == nullptr) GetPrivateValue(); return exponent2; 
        }} 
		public: virtual property Math::BigInteger^ CrtCoefficient { Math::BigInteger^ get()		
        {
			// ������� �������� ���������
			if (coefficient == nullptr) GetPrivateValue(); return coefficient; 
        }} 
		// ���������� ��������� ��������
		private: void GetPrivateValue(); 
	};
}}}}}
