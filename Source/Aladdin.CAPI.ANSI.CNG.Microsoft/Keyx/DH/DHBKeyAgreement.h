#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace DH
{
	//////////////////////////////////////////////////////////////////////////////
	// �������� ������������ ������ �����
	//////////////////////////////////////////////////////////////////////////////
	public ref class BKeyAgreement : CAPI::CNG::BKeyAgreement
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::BigEndian; 
		   
	    // �������� ����������� � ������������� ��������� ���������� �����
		private: CAPI::CNG::Hash^ hashAlgorithm; private: String^ wrapOID; 

		// �����������
		public: BKeyAgreement(String^ provider, CAPI::CNG::Hash^ hashAlgorithm, String^ wrapOID) 
			
			: CAPI::CNG::BKeyAgreement(provider) 
		{
			// ��������� ���������� ���������
			this->hashAlgorithm = RefObject::AddRef(hashAlgorithm); this->wrapOID = wrapOID;
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
		protected: virtual String^ GetName(IParameters^ parameters) override { return BCRYPT_DH_ALGORITHM; }

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
