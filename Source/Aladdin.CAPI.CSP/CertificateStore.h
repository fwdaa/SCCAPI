#pragma once

namespace Aladdin { namespace CAPI { namespace CSP 
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

		// ����� ���������� ��������
		public: array<BYTE>^ FindIssuer(array<BYTE>^ certificate); 

		// ����� ����������
		public: array<BYTE>^ Find(ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo); 
		// ����� ����������
		public: array<BYTE>^ Find(PCERT_PUBLIC_KEY_INFO pInfo); 

		// �������� ����������
		public: void Write(array<BYTE>^ certificate); 

		// �������� ������� ������������ ��������� �����
		public: static array<Certificate^>^ GetCertificateChain(
			String^ provider, DWORD location, Certificate^ certificate
		); 
		// ��������� ������� ������������ ��������� �����
		public: static void SetCertificateChain(
			String^ provider, DWORD location, 
			array<Certificate^>^ certificateChain, int offset  
		); 
	}; 
}}}
