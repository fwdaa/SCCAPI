#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace X962
{
	///////////////////////////////////////////////////////////////////////////
	// ����������� ������
	///////////////////////////////////////////////////////////////////////////
	ref class Encoding abstract sealed 
	{
		// ������ ����������� �����
		public: static const Math::Endian Endian = Math::Endian::BigEndian; 

		// ���������� ��� ���������
		public: static String^ GetKeyName(ANSI::X962::IParameters^ parameters, DWORD keyType);

		// ������������� ������ ��������� �����
		public: static ASN1::ISO::PKIX::SubjectPublicKeyInfo^ GetPublicKeyInfo(
			CAPI::CNG::NKeyHandle^ hPublicKey
		);
		// �������� ��������� ��� ������� ��������� � ������� �����
		public: static DWORD GetKeyPairBlob(String^ algName, ANSI::X962::IPublicKey^ publicKey, 
			ANSI::X962::IPrivateKey^ privateKey, BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob
		); 
		// �������� ��������� ��� ������� ������� �����
		public: static DWORD GetPrivateKeyBlob(String^ algName, ANSI::X962::IPrivateKey^ privateKey, 
			BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob
		); 
		// �������� ��������� ��� ������� ��������� �����
		public: static DWORD GetPublicKeyBlob(String^ algName, ANSI::X962::IPublicKey^ publicKey, 
			BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob
		); 
		// ������������ �������
		public: static array<BYTE>^ EncodeSignature(
			ANSI::X962::IParameters^ parameters, ASN1::ANSI::X962::ECDSASigValue^ signature
		); 
		// ������������� �������
		public: static ASN1::ANSI::X962::ECDSASigValue^ DecodeSignature(
			ANSI::X962::IParameters^ parameters, array<BYTE>^ encoded
		); 
	}; 
}}}}}}
