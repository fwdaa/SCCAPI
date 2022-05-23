#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace ECDH
{
	//////////////////////////////////////////////////////////////////////////////
	// �������� ������������ ������ �����
	//////////////////////////////////////////////////////////////////////////////
	public ref class NKeyAgreement : CAPI::CNG::NKeyAgreement
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::BigEndian; 

		// �������� ����������� � ������������� ��������� ���������� �����
		private: CAPI::CNG::Hash^ hashAlgorithm; ASN1::ISO::AlgorithmIdentifier^ wrapParameters;

		// �����������
		public: NKeyAgreement(CAPI::CNG::Hash^ hashAlgorithm, 
			ASN1::ISO::AlgorithmIdentifier^ wrapParameters)
		{
			// ��������� ���������� ���������
			this->hashAlgorithm = RefObject::AddRef(hashAlgorithm); 

			// ��������� ���������� ���������
            this->wrapParameters = wrapParameters;
		}
		// �����������
		public: virtual ~NKeyAgreement() { RefObject::Release(hashAlgorithm); }

        // ������������� ��������� ������
		public: virtual array<BYTE>^ Generate(IParameters^ parameters, IRand^ rand) override
		{
			// ������� ����� ��� ��������� ������
			array<BYTE>^ random = gcnew array<BYTE>(64); 
			
			// ������������� ��������� ������
			rand->Generate(random, 0, random->Length); return random; 
		}
	    // ����������� ����� ���� �� ������� ����������
		protected: virtual array<BYTE>^ DeriveKey(IParameters^ parameters, 
			CAPI::CNG::NSecretHandle^ hSecret, array<BYTE>^ random, int keySize) override; 
	};
}}}}}}

