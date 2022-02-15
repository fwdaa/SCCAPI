#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace RSA
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
		// �������� ��������� ��� ������� ������� �����
		public: static DWORD GetPrivateKeyBlob(ANSI::RSA::IPrivateKey^ privateKey, 
			BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob
		); 
		// �������� ��������� ��� ������� ��������� �����
		public: static DWORD GetPublicKeyBlob(ANSI::RSA::IPublicKey^ publicKey, 
			BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob
		); 
	}; 
}}}}}}
