using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Aladdin.CAPI 
{
	///////////////////////////////////////////////////////////////////////////
	// Сертификат X509
	///////////////////////////////////////////////////////////////////////////
    public class Certificate
	{
	    public Certificate(Stream stream) 
        {
            // прочитать первый символ
            int first = stream.ReadByte(); if (first < 0) throw new InvalidDataException(); 
        
            // для PEM-кодировки
            if (first == '-') { byte[] encoded = CAPI.PEM.Decode(stream, (byte)first);
        
                // раскодировать сертификат
                ASN1.IEncodable encodable = ASN1.Encodable.Decode(encoded); 
        
                // сохранить содержимое сертификата
                this.certificate = new ASN1.ISO.PKIX.Certificate(encodable); 
            }
            else {
                // раскодировать сертификат
                ASN1.IEncodable encodable = ASN1.Encodable.Decode(stream, (byte)first); 
        
                // сохранить содержимое сертификата
                this.certificate = new ASN1.ISO.PKIX.Certificate(encodable); 
            }
        }
        // конструктор
		public Certificate(byte[] encoded) 
        {
            // обработать PEM-кодировку
            if (encoded.Length != 0 && encoded[0] == '-') encoded = CAPI.PEM.Decode(encoded);

            // раскодировать сертификат
            ASN1.IEncodable encodable = ASN1.Encodable.Decode(encoded); 
        
            // сохранить содержимое сертификата
            this.certificate = new ASN1.ISO.PKIX.Certificate(encodable); 
        }
        // конструктор
		public Certificate(X509Certificate certificate) 
        {
            // раскодировать сертификат
            ASN1.IEncodable encodable = ASN1.Encodable.Decode(
                certificate.GetRawCertData()
            ); 
            // сохранить содержимое сертификата
            this.certificate = new ASN1.ISO.PKIX.Certificate(encodable); 
        }
        // конструктор
		private Certificate(ASN1.ISO.PKIX.Certificate certificate)
        {
            // сохранить содержимое сертификата
            this.certificate = certificate; 
        }
        // раскодированный сертификат
		private ASN1.ISO.PKIX.Certificate certificate;	

        // раскодированный сертификат
        public ASN1.ISO.PKIX.Certificate Decoded { get { return certificate; }} 

		///////////////////////////////////////////////////////////////////////
        // Преобразование типа
		///////////////////////////////////////////////////////////////////////
        public static implicit operator X509Certificate(Certificate certificate)
        {
            // выполнить преобразование типа
            return new X509Certificate2(certificate.Encoded); 
        }
        public static implicit operator X509Certificate2(Certificate certificate)
        {
            // выполнить преобразование типа
            return new X509Certificate2(certificate.Encoded); 
        }
		///////////////////////////////////////////////////////////////////////
		// Методы Object
		///////////////////////////////////////////////////////////////////////
		public override string ToString() 
        { 
            // выполнить преобразование типа
            X509Certificate obj = new X509Certificate2(certificate.Encoded); 

            // вернуть строковое представление
            return obj.ToString(); 
        }
		// получить хэш-код объекта
		public override int GetHashCode() { return certificate.GetHashCode(); }
		
		// сравнение сертификатов
		public override bool Equals(object obj)
		{
			// проверить совпадение сертификатов
			if (obj is Certificate) return Equals((Certificate)obj); 

			// проверить совпадение сертификатов
			if (obj is X509Certificate) return Equals((X509Certificate)obj); 

			return false; 
		}
		public virtual bool Equals(X509Certificate other)
		{
			// проверить совпадение сертификатов
			return certificate.Equals(other); 
		}
		public virtual bool Equals(Certificate other)
		{
			// проверить совпадение сертификатов
			return certificate.Equals(other.certificate); 
		}
		///////////////////////////////////////////////////////////////////////
        // Закодированное представление
		///////////////////////////////////////////////////////////////////////
        public byte[] DER { get { return Encoded; }}

        // закодировать сертификат
        public string PEM { get { 
            
            // закодировать сертификат
            return CAPI.PEM.Encode(Encoded, "CERTIFICATE"); 
        }}
        // закодированное представление 
		public Byte[] Encoded { get { return certificate.Encoded; }}
 
        ///////////////////////////////////////////////////////////////////////
        // Подпись сертификата
        ///////////////////////////////////////////////////////////////////////
        public ASN1.ISO.PKIX.TBSCertificate TBSCertificate
        {
            // подписываемая часть сертификата
            get { return certificate.TBSCertificate; }
        }
	    public ASN1.ISO.AlgorithmIdentifier	SignatureAlgorithm 
        { 
            // описание алгоритма подписи
            get { return certificate.SignatureAlgorithm; } 
        }
        // подпись сертификата
	    public ASN1.BitString Signature	{ get { return certificate.Signature; }}

	    ///////////////////////////////////////////////////////////////////////
	    // Открытый ключ сертификата
	    ///////////////////////////////////////////////////////////////////////
	    public IPublicKey GetPublicKey(Factory factory) 
        { 
            // раскодировать открытый ключ
            return factory.DecodePublicKey(PublicKeyInfo); 
        }
	    public ASN1.ISO.PKIX.SubjectPublicKeyInfo PublicKeyInfo 
        { 
            // закодированный открытый ключ сертификата
            get { return certificate.TBSCertificate.SubjectPublicKeyInfo; }
        }

		///////////////////////////////////////////////////////////////////////
		// Атрибуты сертификата
		///////////////////////////////////////////////////////////////////////
		public Int32 Version { get { return TBSCertificate.Version.Value.IntValue; }}

        // издатель сертификата
	    public ASN1.IEncodable Issuer { get { return TBSCertificate.Issuer; }}

        // имя издателя сертификата
	    public String IssuerName 
        { 
            // имя издателя сертификата
            get { return new X500DistinguishedName(Issuer.Encoded).Name; }
        }
        // идентификатор ключа издателя
        public ASN1.OctetString IssuerKeyIdentifier { get
        { 
            // получить расширения сертификата
            ASN1.ISO.PKIX.Extensions extensions = Extensions; 
            
            // проверить наличие расширений
            if (extensions == null) return null;
            try { 
                // получить требуемое расширение
                ASN1.ISO.PKIX.CE.AuthorityKeyIdentifier extension = extensions.AuthorityKeyIdentifier; 

                // вернуть идентификатор ключа издателя
                return (extension != null) ? extension.KeyIdentifier : null; 
            }
            // обработать возможную ошибку
            catch { return null; }
        }}
        // серийный номер сертификата
	    public Math.BigInteger SerialNumber 
        { 
            // серийный номер сертификата
            get { return TBSCertificate.SerialNumber.Value; } 
        }
        // издатель и серийный номер сертификата
        public ASN1.ISO.PKIX.IssuerSerialNumber IssuerSerialNumber 
        { 
            // издатель и серийный номер сертификата
            get { return TBSCertificate.IssuerSerialNumber; } 
        }
        // субъект сертификата
	    public ASN1.IEncodable Subject { get { return TBSCertificate.Subject; }}

        // имя субъекта сертификата
	    public String SubjectName 
        { 
            // имя субъекта сертификата
            get { return new X500DistinguishedName(Subject.Encoded).Name; } 
        }
        // идентификатор ключа субъекта
        public ASN1.OctetString SubjectKeyIdentifier { get 
        { 
            // получить расширения сертификата
            ASN1.ISO.PKIX.Extensions extensions = Extensions; 
            
            // проверить наличие расширений
            if (extensions == null) return null;
            try { 
                // вернуть идентификатор ключа субъекта
                return extensions.SubjectKeyIdentifier; 
            }
            // обработать возможную ошибку
            catch { return null; }
        }}
        // срок действия сертификата
	    public DateTime NotBefore { get { return TBSCertificate.Validity.NotBeforeDate; }}
	    public DateTime NotAfter  { get { return TBSCertificate.Validity.NotAfterDate;  }}

        ///////////////////////////////////////////////////////////////////////
        // Расширения сертификата
        ///////////////////////////////////////////////////////////////////////
	    public ASN1.ISO.PKIX.Extensions	Extensions { get { return TBSCertificate.Extensions; }}

        // способ использования ключа
        public KeyUsage KeyUsage { get 
        { 
            // получить расширения сертификата
            ASN1.ISO.PKIX.Extensions extensions = Extensions; 
            
            // проверить наличие расширений
            if (extensions == null) return KeyUsage.None;
            try {    
                // вернуть способ использования ключа
                return (KeyUsage)extensions.KeyUsage;             
            }
            // обработать возможную ошибку
            catch { return KeyUsage.None; }
        }}
        // расширенные способы использования ключа
        public String[] ExtendedKeyUsage { get 
        { 
            // получить расширения сертификата
            ASN1.ISO.PKIX.Extensions extensions = Extensions; 
            
            // проверить наличие расширений
            if (extensions == null) return null;
            try {    
                // получить расширенные способы использования ключа
                ASN1.ISO.PKIX.CE.ExtKeyUsageSyntax 
                    extendedKeyUsage = extensions.ExtendedKeyUsage;  
            
                // проверить наличие расширенных способов
                if (extendedKeyUsage == null) return null; 
            
                // выделить память для результата
                String[] oids = new String[extendedKeyUsage.Length]; 
                
                // извлечь дополнительные назначения ключа
                for (int i = 0; i < oids.Length; i++) 
                {
                    oids[i] = extendedKeyUsage[i].Value; 
                }
                return oids;             
            }
            // обработать возможную ошибку
            catch { return null; }
        }}
    }
}
