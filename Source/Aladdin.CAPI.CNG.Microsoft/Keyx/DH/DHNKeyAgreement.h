#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace DH
{
	//////////////////////////////////////////////////////////////////////////////
	// �������� ������������ ������ �����
	//////////////////////////////////////////////////////////////////////////////
	public ref class NKeyAgreement : CAPI::CNG::NKeyAgreement
	{
		// ������ ����������� �����
		protected: static const Math::Endian Endian = Math::Endian::BigEndian; 

		// �������� ����������� � ������������� ��������� ���������� �����
		private: CAPI::CNG::Hash^ hashAlgorithm; private: String^ wrapOID; 

		// �����������
		public: NKeyAgreement(CAPI::CNG::Hash^ hashAlgorithm, String^ wrapOID)
		{
			// ��������� ���������� ���������
			this->hashAlgorithm = RefObject::AddRef(hashAlgorithm); this->wrapOID = wrapOID;
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


