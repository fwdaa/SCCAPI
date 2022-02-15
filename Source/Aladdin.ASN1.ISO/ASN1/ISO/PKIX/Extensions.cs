using System;
using System.Collections.Generic;
using System.IO;

// Extensions ::= SEQUENCE OF Extension

namespace Aladdin.ASN1.ISO.PKIX
{
	public class Extensions : Sequence<Extension>
	{
		// конструктор при раскодировании
		public Extensions(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public Extensions(params Extension[] values) : base(values) {}

		// конструктор при закодировании
		public Extensions(Attribute attribute) 
			
			// извлечь расширения из атрибута
			: base(ExtractExtensions(attribute)) {} 

		private static Extension[] ExtractExtensions(Attribute attribute)
		{
			// проверить тип атрибута
			if (attribute.Type.Value != ASN1.ISO.PKCS.PKCS9.OID.extensionRequest)
			{
				// при ошибке выбросить исключение
				throw new InvalidDataException(); 
			}
			// создать пустой список расширений
			List<Extension> extensions = new List<Extension>(); 

			// извлечь расширения для сертификата
			Set<Extensions> setExtensions = new Set<Extensions>(attribute.Values); 

			// добавить расширения в список
			foreach (Extensions exts in setExtensions) extensions.AddRange(exts); 

			// вернуть расширения из атрибута
			return extensions.ToArray(); 
		}
		public IEncodable this[string oid] { get 
		{
			// для всех параметров
			foreach (Extension extension in this)
			{
				// проверить совпадение идентификатора
				if (extension.ExtnID.Value == oid) return extension.ExtnValue; 
			}
			return null; 
		}}
        public OctetString SubjectKeyIdentifier { get  
        {
            // получить расширение
            ASN1.IEncodable value = this[OID.ce_subjectKeyIdentifier]; 

            // раскодировать расширение
            return (value != null) ? new OctetString(value) : null; 
        }}
        public CE.AuthorityKeyIdentifier AuthorityKeyIdentifier { get  
        {
            // получить расширение
            ASN1.IEncodable value = this[OID.ce_authorityKeyIdentifier]; 

            // раскодировать расширение
            if (value != null) return new CE.AuthorityKeyIdentifier(value); 

            // получить расширение
            value = this[OID.ce_authorityKeyIdentifier_old]; if (value != null)
            {
                // раскодировать расширение
                return new CE.AuthorityKeyIdentifierOld(value).Update(); 
            }
            return null; 
        }}
        public CE.KeyUsage KeyUsage { get 
        {
            // получить расширение
            ASN1.IEncodable value = this[OID.ce_keyUsage]; 

            // проверить наличие расширения
            if (value == null) return CE.KeyUsage.None;
            
            // раскодировать расширение
            BitFlags flags = new BitFlags(value); return (CE.KeyUsage)flags.Value; 
        }}
        public CE.ExtKeyUsageSyntax ExtendedKeyUsage { get 
        {
            // получить расширение
            ASN1.IEncodable value = this[OID.ce_extKeyUsage]; 

            // раскодировать расширение
            return (value != null) ? new CE.ExtKeyUsageSyntax(value) : null; 
        }}
        public CE.BasicConstraints BasicConstraints { get 
        {
            // получить расширение
            ASN1.IEncodable value = this[OID.ce_basicConstraints]; 

            // раскодировать расширение
            return (value != null) ? new CE.BasicConstraints(value) : null; 
        }}
        public CE.CertificatePolicies CertificatePolicies { get 
        {
            // получить расширение
            ASN1.IEncodable value = this[OID.ce_certificatePolicies]; 

            // раскодировать расширение
            return (value != null) ? new CE.CertificatePolicies(value) : null; 
        }}
	}
}
