using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Aladdin.CAPI 
{
	///////////////////////////////////////////////////////////////////////////
	// Запрос на сертификат X509
	///////////////////////////////////////////////////////////////////////////
    public class CertificateRequest
	{
		// конструктор
	    public CertificateRequest(Stream stream)
        {
            // прочитать первый символ
            int first = stream.ReadByte(); if (first < 0) throw new InvalidDataException(); 
        
            // для PEM-кодировки
            if (first == '-') { byte[] encoded = CAPI.PEM.Decode(stream, (byte)first);
        
                // раскодировать сертификат
                ASN1.IEncodable encodable = ASN1.Encodable.Decode(encoded); 
        
                // сохранить содержимое запроса на сертификат
                this.request = new ASN1.ISO.PKCS.PKCS10.CertificationRequest(encodable); 
            }
            else {
                // раскодировать сертификат
                ASN1.IEncodable encodable = ASN1.Encodable.Decode(stream, (byte)first); 
        
                // сохранить содержимое сертификата
                this.request = new ASN1.ISO.PKCS.PKCS10.CertificationRequest(encodable); 
            }
        }
		// конструктор
		public CertificateRequest(byte[] encoded) 
        {
            // обработать PEM-кодировку
            if (encoded.Length != 0 && encoded[0] == '-') encoded = CAPI.PEM.Decode(encoded);

            // раскодировать запрос на сертификат
            ASN1.IEncodable encodable = ASN1.Encodable.Decode(encoded); 
        
            // сохранить содержимое запроса на сертификат
            this.request = new ASN1.ISO.PKCS.PKCS10.CertificationRequest(encodable); 
        }
		// конструктор
		private CertificateRequest(ASN1.ISO.PKCS.PKCS10.CertificationRequest request)
        {
			// сохранить переданные параметры
			this.request = request; 
        }
        // раскодированный запрос на сертификат
		private ASN1.ISO.PKCS.PKCS10.CertificationRequest request;	
	
        // раскодированный запрос на сертификат
        public ASN1.ISO.PKCS.PKCS10.CertificationRequest Decoded { get { return request; }}

		///////////////////////////////////////////////////////////////////////
		// Методы Object
		///////////////////////////////////////////////////////////////////////
		
		// получить хэш-код объекта
		public override int GetHashCode() { return request.GetHashCode(); }
		
		// сравнение запросов на сертификат
		public override bool Equals(object obj)
		{
			// проверить совпадение запросов на сертификат
			if (obj is CertificateRequest) return Equals((CertificateRequest)obj); 

			return false; 
		}
		public virtual bool Equals(CertificateRequest other)
		{
			// проверить совпадение запросов на сертификат
			return request.Equals(other.request); 
		}
		///////////////////////////////////////////////////////////////////////
        // Закодированное представление
		///////////////////////////////////////////////////////////////////////
        public byte[] DER { get { return Encoded; }}

        // закодировать запрос на сертификат
        public string PEM { get { 
            
            // закодировать запрос на сертификат
            return CAPI.PEM.Encode(Encoded, "CERTIFICATE REQUEST"); 
        }}
        // закодированное представление
		public Byte[] Encoded { get { return request.Encoded; }} 

        ///////////////////////////////////////////////////////////////////////
        // Подпись запроса на сертификат
        ///////////////////////////////////////////////////////////////////////
        public ASN1.ISO.PKCS.PKCS10.CertificationRequestInfo TBSCertificateRequest
        {
            // подписываемая часть запроса на сертификат
            get { return request.CertificationRequestInfo; }
        }
        // описание алгоритма подписи
	    public ASN1.ISO.AlgorithmIdentifier SignatureAlgorithm	
        { 
            // описание алгоритма подписи
            get { return request.SignatureAlgorithm; }
        }
        // подпись запроса на сертификат
	    public ASN1.BitString Signature { get { return request.Signature; }}

	    ///////////////////////////////////////////////////////////////////////
	    // Открытый ключ запроса на сертификат
	    ///////////////////////////////////////////////////////////////////////
	    public IPublicKey GetPublicKey(Factory factory) 
        { 
            // раскодировать открытый ключ
            return factory.DecodePublicKey(PublicKeyInfo); 
        }
        // закодированный открытый ключ запроса на сертификат
		public ASN1.ISO.PKIX.SubjectPublicKeyInfo PublicKeyInfo 
        { 
            // закодированный открытый ключ запроса на сертификат
            get { return TBSCertificateRequest.SubjectPKInfo; }
        }
		///////////////////////////////////////////////////////////////////////
		// Атрибуты сертификата
		///////////////////////////////////////////////////////////////////////
		public Int32 Version { get { return TBSCertificateRequest.Version.Value.IntValue; }}

        // субъект запроса на сертификат
		public ASN1.IEncodable Subject { get { return TBSCertificateRequest.Subject; }}

        // имя субъекта запроса на сертификат
	    public String SubjectName 
        { 
            // имя субъекта запроса на сертификат
            get { return new X500DistinguishedName(Subject.Encoded).Name; } 
        }
        // атрибуты запроса на сертификат
		public ASN1.ISO.Attributes Attributes { get { return TBSCertificateRequest.Attributes; }}

        ///////////////////////////////////////////////////////////////////////
        // Расширения запроса на сертификат
        ///////////////////////////////////////////////////////////////////////
		public ASN1.ISO.PKIX.Extensions Extensions { get 
        { 
		    // для всех атрибутов запроса
            foreach (ASN1.ISO.Attribute attribute in Attributes)
		    {
			    // для атрибутов расширений
			    if (attribute.Type.Value == ASN1.ISO.PKCS.PKCS9.OID.extensionRequest)
			    {
				    // извлечь расширения для сертификата
				    return new ASN1.ISO.PKIX.Extensions(attribute);
			    }
            }
            return null; 
        }}
        // способ использования ключа
	    public KeyUsage KeyUsage { get 
        { 
            // получить расширения запроса на сертификат
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
    }
}
