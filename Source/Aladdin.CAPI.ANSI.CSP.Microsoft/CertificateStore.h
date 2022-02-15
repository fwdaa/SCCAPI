#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft
{
	//////////////////////////////////////////////////////////////////////////////
	// Хранилище сертификатов
	//////////////////////////////////////////////////////////////////////////////
	public ref class CertificateStore : IDisposable
	{
		// описатель хранилища
		private: HCERTSTORE hCertStore; 

		// конструктор
		public: CertificateStore(String^ provider, String^ name, DWORD location); 
		// деструктор
		public: virtual ~CertificateStore(); 

		// найти сертификат
		public: array<BYTE>^ Find(ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo); 
		// найти сертификат
		public: array<BYTE>^ Find(PCERT_PUBLIC_KEY_INFO pInfo); 

		// записать сертификат
		public: void Write(array<BYTE>^ certificate); 
	}; 
}}}}}
