#pragma once

namespace Aladdin { namespace CAPI { namespace CSP 
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

		// найти сертификат издателя
		public: array<BYTE>^ FindIssuer(array<BYTE>^ certificate); 

		// найти сертификат
		public: array<BYTE>^ Find(ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo); 
		// найти сертификат
		public: array<BYTE>^ Find(PCERT_PUBLIC_KEY_INFO pInfo); 

		// записать сертификат
		public: void Write(array<BYTE>^ certificate); 

		// получить цепочку сертификатов открытого ключа
		public: static array<Certificate^>^ GetCertificateChain(
			String^ provider, DWORD location, Certificate^ certificate
		); 
		// сохранить цепочку сертификатов открытого ключа
		public: static void SetCertificateChain(
			String^ provider, DWORD location, 
			array<Certificate^>^ certificateChain, int offset  
		); 
	}; 
}}}
