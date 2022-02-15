#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace X942
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
		public: static DWORD GetParametersBlob(ANSI::X942::IParameters^ parameters, 
			BCRYPT_DH_PARAMETER_HEADER* pBlob, DWORD cbBlob
		); 
		// �������� ��������� ��� ������� ��������� � ������� �����
		public: static DWORD GetKeyPairBlob(ANSI::X942::IPublicKey^ publicKey, 
			ANSI::X942::IPrivateKey^ privateKey, BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob
		); 
		// �������� ��������� ��� ������� ������� �����
		public: static DWORD GetPrivateKeyBlob(ANSI::X942::IPrivateKey^ privateKey, 
			BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob
		); 
		// �������� ��������� ��� ������� ��������� �����
		public: static DWORD GetPublicKeyBlob(ANSI::X942::IPublicKey^ publicKey, 
			BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob
		); 
	}; 
}}}}}}
