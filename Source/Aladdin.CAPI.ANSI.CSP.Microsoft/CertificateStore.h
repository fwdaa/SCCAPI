#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft
{
	//////////////////////////////////////////////////////////////////////////////
	// ��������� ������������
	//////////////////////////////////////////////////////////////////////////////
	public ref class CertificateStore : IDisposable
	{
		// ��������� ���������
		private: HCERTSTORE hCertStore; 

		// �����������
		public: CertificateStore(String^ provider, String^ name, DWORD location); 
		// ����������
		public: virtual ~CertificateStore(); 

		// ����� ����������
		public: array<BYTE>^ Find(ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo); 
		// ����� ����������
		public: array<BYTE>^ Find(PCERT_PUBLIC_KEY_INFO pInfo); 

		// �������� ����������
		public: void Write(array<BYTE>^ certificate); 
	}; 
}}}}}