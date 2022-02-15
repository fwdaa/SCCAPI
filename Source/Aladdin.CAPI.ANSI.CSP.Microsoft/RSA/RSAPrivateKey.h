#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ���� RSA
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::CSP::PrivateKey, CAPI::ANSI::RSA::IPrivateKey
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		private: Math::BigInteger^ modulus;         // �������� N	
		private: Math::BigInteger^ publicExponent;  // �������� E
		private: Math::BigInteger^ privateExponent; // �������� D
		private: Math::BigInteger^ prime1;          // �������� P
		private: Math::BigInteger^ prime2;          // �������� Q
		private: Math::BigInteger^ exponent1;       // �������� D (mod P-1)
		private: Math::BigInteger^ exponent2;       // �������� D (mod Q-1)
		private: Math::BigInteger^ coefficient;     // �������� Q^{-1}(mod P)

		// �����������
		public: PrivateKey(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, ANSI::RSA::IPublicKey^ publicKey, 
			CAPI::CSP::KeyHandle^ hKeyPair, array<BYTE>^ keyID, DWORD keyType)

			// ��������� ���������� ���������
			: CAPI::CSP::PrivateKey(provider, scope, publicKey, hKeyPair, keyID, keyType) {} 

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
}}}}}}