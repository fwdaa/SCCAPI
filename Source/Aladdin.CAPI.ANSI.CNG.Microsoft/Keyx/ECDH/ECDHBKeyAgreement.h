#pragma once
#include "..\..\X962\X962Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace ECDH
{
	//////////////////////////////////////////////////////////////////////////////
	// �������� ������������ ������ �����
	//////////////////////////////////////////////////////////////////////////////
	public ref class BKeyAgreement : CAPI::CNG::BKeyAgreement
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::BigEndian; 

		// �������� ����������� � ������������� ��������� ���������� �����
		private: CAPI::CNG::Hash^ hashAlgorithm; ASN1::ISO::AlgorithmIdentifier^ wrapParameters; 

		// �����������
		public: BKeyAgreement(String^ provider, CAPI::CNG::Hash^ hashAlgorithm, 
			ASN1::ISO::AlgorithmIdentifier^ wrapParameters) 
			
			: CAPI::CNG::BKeyAgreement(provider) 
		{
			// ��������� ���������� ���������
			this->hashAlgorithm = RefObject::AddRef(hashAlgorithm); 

			// ��������� ���������� ���������
            this->wrapParameters = wrapParameters;
		}
		// �����������
		public: virtual ~BKeyAgreement() { RefObject::Release(hashAlgorithm); }

        // ������������� ��������� ������
		public: virtual array<BYTE>^ Generate(IParameters^ parameters, IRand^ rand) override
		{
			// ������� ����� ��� ��������� ������
			array<BYTE>^ random = gcnew array<BYTE>(64); 
			
			// ������������� ��������� ������
			rand->Generate(random, 0, random->Length); return random; 
		}
		// ��� ���������
		protected: virtual String^ GetName(IParameters^ parameters) override
		{
			// ������� ��� ���������
			return X962::Encoding::GetKeyName((ANSI::X962::IParameters^)parameters, AT_KEYEXCHANGE); 
		}
		// ������������� ������ ����
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPrivateKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) override; 

		// ������������� �������� ����
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPublicKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) override; 

	    // ����������� ����� ���� �� ������� ����������
		protected: virtual array<BYTE>^ DeriveKey(IParameters^ parameters, 
			CAPI::CNG::BSecretHandle^ hSecret, array<BYTE>^ random, int keySize) override; 
	};
}}}}}}}
