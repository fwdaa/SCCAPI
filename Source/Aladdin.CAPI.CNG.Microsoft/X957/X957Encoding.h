#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace X957
{
	///////////////////////////////////////////////////////////////////////////
	// ����������� ������
	///////////////////////////////////////////////////////////////////////////
	ref class Encoding abstract sealed 
	{
		// ������ ����������� �����
		public: static const Math::Endian Endian = Math::Endian::BigEndian; 

		// ������������� ������ ��������� �����
		public: static ASN1::ISO::PKIX::SubjectPublicKeyInfo^ GetPublicKeyInfo(
			CAPI::CNG::NKeyHandle^ hPublicKey
		);
		// �������� ��������� ��� ������� ����������
		public: static DWORD GetParametersBlob(ANSI::X957::IParameters^ parameters, 
			BCRYPT_DSA_PARAMETER_HEADER* pBlob, DWORD cbBlob
		); 
		// �������� ��������� ��� ������� ��������� � ������� �����
		public: static DWORD GetKeyPairBlob(ANSI::X957::IPublicKey^ publicKey, 
			ANSI::X957::IPrivateKey^ privateKey, BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob
		); 
		// �������� ��������� ��� ������� ������� �����
		public: static DWORD GetPrivateKeyBlob(ANSI::X957::IPrivateKey^ privateKey, 
			BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob
		); 
		// �������� ��������� ��� ������� ��������� �����
		public: static DWORD GetPublicKeyBlob(ANSI::X957::IPublicKey^ publicKey, 
			BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob
		); 
		// ������������ �������
		public: static array<BYTE>^ EncodeSignature(
			ANSI::X957::IParameters^ parameters, ASN1::ANSI::X957::DssSigValue^ signature
		); 
		// ������������� �������
		public: static ASN1::ANSI::X957::DssSigValue^ DecodeSignature(
			ANSI::X957::IParameters^ parameters, array<BYTE>^ encoded
		); 
	}; 
}}}}}
