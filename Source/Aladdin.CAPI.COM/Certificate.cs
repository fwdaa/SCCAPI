using System;
using System.IO;
using System.Globalization;
using System.Threading;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.COM
{
	///////////////////////////////////////////////////////////////////////////
	// Cертификат 
	///////////////////////////////////////////////////////////////////////////
    [ClassInterface(ClassInterfaceType.None)]
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class Certificate : RefObject, ICertificate
	{
		private CryptoEnvironment	environment;	// среда окружения
		private CultureInfo			cultureInfo;	// локализация
		private CAPI.Certificate	certificate;	// сертификат

		// конструктор
		public Certificate(CryptoEnvironment environment, 
            CultureInfo cultureInfo, CAPI.Certificate certificate) 
		{
            // сохранить переданные параметры
			this.environment = RefObject.AddRef(environment);

            // сохранить переданные параметры
			this.cultureInfo = cultureInfo; this.certificate = certificate;
		}
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(environment); base.OnDispose(); 
        }
		// получить строковое представление
		public virtual string Encoded { get 
        { 
		    // получить строковое представление
            return Convert.ToBase64String(certificate.Encoded); 
        }}
		///////////////////////////////////////////////////////////////////////
		// Идентификатор (OID) ключа
		///////////////////////////////////////////////////////////////////////
		public virtual string KeyOID
		{
			// вернуть идентификатор (OID) ключа
			get { return certificate.PublicKeyInfo.Algorithm.Algorithm.Value; }
		}
		///////////////////////////////////////////////////////////////////////
		// Имена издателя и субъекта
		///////////////////////////////////////////////////////////////////////
		public virtual IDistinctName Issuer  { get 
		{ 
			// отличимое имя издателя
			return new DistinctName(certificate.IssuerName, certificate.Issuer.Encoded);  
		}}
		public virtual IDistinctName Subject { get 
		{
			// отличимое имя субъекта
			return new DistinctName(certificate.SubjectName, certificate.Subject.Encoded);
		}}
		///////////////////////////////////////////////////////////////////////
	    // Способ использования сертификата
		///////////////////////////////////////////////////////////////////////
	    public virtual KeyUsage KeyUsage 
        { 
            get { return (KeyUsage)certificate.KeyUsage; } 
        }
		///////////////////////////////////////////////////////////////////////
		// Зашифровать данные на сертификате
		///////////////////////////////////////////////////////////////////////
		public virtual string Encrypt(string data)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
				// раскодировать данные
				byte[] decoded = Convert.FromBase64String(data);

				// зашифровать данные на открытом ключе
				byte[] encrypted = Encrypt(decoded);

				// закодировать данные
				return Convert.ToBase64String(encrypted);
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
		[ComVisible(false)] 
		public byte[] Encrypt(byte[] data)
		{
            // указать тип данных
            CMSData cmsData = new CMSData(ASN1.ISO.PKCS.PKCS7.OID.data, data); 

			// указать генератор случайных данных
			using (IRand rand = environment.CreateRand(null))
			{ 
				// зашифровать данные на открытом ключе
				ASN1.ISO.PKCS.ContentInfo contentInfo = Culture.KeyxEncryptData(
					null, environment.Factories, null, rand, certificate, cmsData, null
				); 
				// вернуть зашифрованные данные
				return contentInfo.Encoded; 
			}
		}
		///////////////////////////////////////////////////////////////////////
		// Проверить подпись данных на сертификате
		///////////////////////////////////////////////////////////////////////
		public virtual string VerifySign(string data)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
				// раскодировать данные
				byte[] decoded = Convert.FromBase64String(data);

				// проверить подпись данных
				byte[] content = VerifySign(decoded);

				// закодировать данные
				return Convert.ToBase64String(content);
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
		[ComVisible(false)] 
		public byte[] VerifySign(byte[] data)
		{
			// интерпретировать данные в формате ContentInfo
			ASN1.ISO.PKCS.ContentInfo contentInfo = 
                new ASN1.ISO.PKCS.ContentInfo(ASN1.Encodable.Decode(data));

			// проверить тип данных
			if (contentInfo.ContentType.Value != 
				ASN1.ISO.PKCS.PKCS7.OID.signedData) throw new InvalidDataException(); 

			// интерпретировать данные в формате SignedData
			ASN1.ISO.PKCS.PKCS7.SignedData signedData = 
				new ASN1.ISO.PKCS.PKCS7.SignedData(contentInfo.Inner);

		    // проверить подпись данных
		    CMS.VerifySign(environment.Factories, null, certificate, signedData); 

			// вернуть исходный текст
			return signedData.EncapContentInfo.EContent.Value; 
		}
	}
}
