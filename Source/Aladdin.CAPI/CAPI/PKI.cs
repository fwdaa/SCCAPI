using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates; 
using System.IO;

namespace Aladdin.CAPI
{
	public static class PKI
	{
		///////////////////////////////////////////////////////////////////////
		// Закодировать отличимое имя
		///////////////////////////////////////////////////////////////////////
		public static ASN1.IEncodable EncodeDistinguishedName(string name)
		{
			// закодировать отличимое имя
			return ASN1.Encodable.Decode(new X500DistinguishedName(name).RawData); 
		}
		///////////////////////////////////////////////////////////////////////
		// Объединить расширения
		///////////////////////////////////////////////////////////////////////
        public static ASN1.ISO.PKIX.Extensions AddExtensions(
            ASN1.ISO.PKIX.Extensions extensions, KeyUsage keyUsage, 
            String[] extKeyUsage, ASN1.ISO.PKIX.CE.BasicConstraints basicConstraints, 
            ASN1.ISO.PKIX.CE.CertificatePolicies policies)
        {
            // создать список расширений
            List<ASN1.ISO.PKIX.Extension> listExtensions = new List<ASN1.ISO.PKIX.Extension>(); 

            // при указании использования ключа
            if (keyUsage != KeyUsage.None)
            {
                // добавить расширение
                listExtensions.Add(new ASN1.ISO.PKIX.Extension(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKIX.OID.ce_keyUsage), 
				    ASN1.Boolean.True, new ASN1.BitFlags(keyUsage)
                ));
            }
            // при указании использования ключа
            if (extKeyUsage != null && extKeyUsage.Length != 0) 
            { 
                // создать список идентификаторов
                ASN1.ObjectIdentifier[] oids = new ASN1.ObjectIdentifier[extKeyUsage.Length]; 

                // указать признак критичности
                ASN1.Boolean critical = ASN1.Boolean.True; 

                // для всех идентификаторов
                for (int i = 0; i < extKeyUsage.Length; i++)
                {
                    // скорректировать признак критичности
                    if (extKeyUsage[i] == ASN1.ISO.PKIX.OID.ce_extKeyUsage_any) critical = ASN1.Boolean.False; 

                    // закодировать идентификатор
                    oids[i] = new ASN1.ObjectIdentifier(extKeyUsage[i]); 
                }
                // добавить расширение
                listExtensions.Add(new ASN1.ISO.PKIX.Extension(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKIX.OID.ce_extKeyUsage), 
				    critical, new ASN1.ISO.PKIX.CE.ExtKeyUsageSyntax(oids)
                ));
            }
            // при наличии расширения
            if (basicConstraints != null)
            {
                // добавить расширение
                listExtensions.Add(new ASN1.ISO.PKIX.Extension(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKIX.OID.ce_basicConstraints), 
                    ASN1.Boolean.True, basicConstraints
                ));
            }
            // при наличии политик
            if (policies != null && policies.Length > 0)
            {
                // добавить расширение
                listExtensions.Add(new ASN1.ISO.PKIX.Extension(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKIX.OID.ce_certificatePolicies), 
                    ASN1.Boolean.True, policies
                ));
            }
            // при наличии расширений
            if (extensions != null && extensions.Length > 0) 
            { 
                // для всех расширений
                foreach (ASN1.ISO.PKIX.Extension extension in extensions)
                {
                    // добавить расширение в список
                    listExtensions.Add(extension); 
                }
            }
            // проверить наличие расширений
            if (listExtensions.Count == 0) return null; 

            // объединить расширения
            return new ASN1.ISO.PKIX.Extensions(listExtensions.ToArray()); 
        }
		///////////////////////////////////////////////////////////////////////
		// Создать запрос PKCS10 на сертификат X.509
		///////////////////////////////////////////////////////////////////////
        public static CertificateRequest CreateCertificationRequest(IRand rand, 
            ASN1.IEncodable subject, ASN1.ISO.AlgorithmIdentifier signParameters, 
            IPublicKey publicKey, IPrivateKey privateKey, ASN1.ISO.PKIX.Extensions extensions)
        {
            // закодировать открытый ключ
            ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = publicKey.Encoded; 

            // создать список расширений
            List<ASN1.ISO.PKIX.Extension> listExtensions = new List<ASN1.ISO.PKIX.Extension>(); 

            // при наличии расширений
            if (extensions != null && extensions.Length > 0) 
            { 
                // для всех расширений
                foreach (ASN1.ISO.PKIX.Extension extension in extensions)
                {
                    // проверить допустимостиь расширения
                    if (extension.ExtnID.Value != ASN1.ISO.PKIX.OID.ce_subjectKeyIdentifier   && 
                        extension.ExtnID.Value != ASN1.ISO.PKIX.OID.ce_authorityKeyIdentifier &&
                        extension.ExtnID.Value != ASN1.ISO.PKIX.OID.ce_authorityKeyIdentifier_old)
                    {
                        // добавить расширение в список
                        listExtensions.Add(extension); 
                    }
                }
            }
		    // создать значение атрибута
		    ASN1.Set<ASN1.ISO.PKIX.Extensions> attributeValue = 
			    new ASN1.Set<ASN1.ISO.PKIX.Extensions>(new ASN1.ISO.PKIX.Extensions[] { 
                    new ASN1.ISO.PKIX.Extensions(listExtensions.ToArray())
            });
		    // создать атрибут запроса на сертификат
			ASN1.ISO.Attribute attribute = new ASN1.ISO.Attribute(
			    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.extensionRequest), attributeValue
			); 
		    // создать множество атрибутов
		    ASN1.ISO.Attributes attributes = new ASN1.ISO.Attributes(new ASN1.ISO.Attribute[] {attribute}); 

			// создать запрос на сертификат
			ASN1.ISO.PKCS.PKCS10.CertificationRequestInfo certificationRequestInfo = 
				new ASN1.ISO.PKCS.PKCS10.CertificationRequestInfo(
					new ASN1.Integer(0), subject, publicKeyInfo, attributes
			); 
			// извлечь подписываемые данные
			byte[] data = certificationRequestInfo.Encoded; 

            // при отсутствии параметров подписи
            if (signParameters == null) 
            {
                // получить алгоритмы по умолчанию
                Culture culture = privateKey.Factory.GetCulture(
                    privateKey.Scope, publicKey.KeyOID
                ); 
                // указать параметры алгоритма подписи
                signParameters = culture.SignDataAlgorithm(rand); 
            
                // проверить указание алгоритма
                if (signParameters == null) throw new NotSupportedException();
            }
            // при отсутствии алгоритма
            if (signParameters.Algorithm.Value == "2.5.8.0")
            {
                // создать пустую подпись
                ASN1.BitString signature = new ASN1.BitString(new byte[0]); 
            
                // создать запрос на сертификат
                ASN1.ISO.PKCS.PKCS10.CertificationRequest request = 
                    new ASN1.ISO.PKCS.PKCS10.CertificationRequest(
                        certificationRequestInfo, signParameters, signature
                ); 
                // вернуть запрос на сертификат
                return new CertificateRequest(request.Encoded);
            }
            // создать алгоритм подписи
		    using (SignData signAlgorithm = privateKey.Factory.
                CreateAlgorithm<SignData>(privateKey.Scope, signParameters))
            { 
		        // при ошибке выбросить исключение
		        if (signAlgorithm == null) throw new NotSupportedException();

                // вычислить подпись данных
                ASN1.BitString signature = new ASN1.BitString(
                    signAlgorithm.Sign(privateKey, rand, data, 0, data.Length)
                ); 
                // создать запрос на сертификат
                ASN1.ISO.PKCS.PKCS10.CertificationRequest request = 
                    new ASN1.ISO.PKCS.PKCS10.CertificationRequest(
		                certificationRequestInfo, signParameters, signature
	            ); 
	            // вернуть запрос на сертификат
	            return new CertificateRequest(request.Encoded); 
            }
        }
        public static CertificateRequest CreateCertificationRequest(IRand rand, 
            ASN1.IEncodable subject, ASN1.ISO.AlgorithmIdentifier signParameters, 
            IPublicKey publicKey, IPrivateKey privateKey, KeyUsage keyUsage, 
            String[] extKeyUsage, ASN1.ISO.PKIX.CE.BasicConstraints basicConstraints, 
            ASN1.ISO.PKIX.CE.CertificatePolicies policies, ASN1.ISO.PKIX.Extensions extensions)
		{
            // объединить расширения
            extensions = AddExtensions(extensions, keyUsage, extKeyUsage, basicConstraints, policies); 

            // создать запрос на сертификат
            return CreateCertificationRequest(rand, subject, signParameters, publicKey, privateKey, extensions); 
		}
		///////////////////////////////////////////////////////////////////////
		// Создать сертификат X.509
		///////////////////////////////////////////////////////////////////////
		public static Certificate CreateCertificate(IRand rand, 
			ASN1.IEncodable issuer, ASN1.Integer serial, ASN1.IEncodable subject, 
			ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo, 
            DateTime notBefore, DateTime notAfter, 
			ASN1.ISO.AlgorithmIdentifier signParameters, IPrivateKey privateKey, 
            ASN1.ISO.PKIX.Extension[] extensions)
		{
            // указать значения по умолчанию
            ASN1.ISO.PKIX.Extensions exts = null; ASN1.Integer version = new ASN1.Integer(0);

            // при наличии расширений
            if (extensions != null && extensions.Length > 0) { version = new ASN1.Integer(2); 
             
                // объединить расширения
                exts = new ASN1.ISO.PKIX.Extensions(extensions);
            }
			// закодировать срок действия
			ASN1.GeneralizedTime encodedNotBefore = new ASN1.GeneralizedTime(notBefore); 
			ASN1.GeneralizedTime encodedNotAfter  = new ASN1.GeneralizedTime(notAfter ); 

			// создать описание срока действия
			ASN1.ISO.PKIX.Validity validity = new ASN1.ISO.PKIX.Validity(
				encodedNotBefore, encodedNotAfter
			); 
			// создать информацию сертификата
			ASN1.ISO.PKIX.TBSCertificate tbsCertificate = new ASN1.ISO.PKIX.TBSCertificate(
                version, serial, signParameters, issuer, 
                validity, subject, publicKeyInfo, null, null, exts
			);
            // извлечь подписываемые данные
            byte[] data = tbsCertificate.Encoded;

            // создать алгоритм подписи
			using (SignData signAlgorithm = privateKey.Factory.
                CreateAlgorithm<SignData>(privateKey.Scope, signParameters))
            { 
			    // при ошибке выбросить исключение
			    if (signAlgorithm == null) throw new NotSupportedException();

	            // вычислить подпись данных
	            ASN1.BitString signature = new ASN1.BitString(
                    signAlgorithm.Sign(privateKey, rand, data, 0, data.Length)
                ); 
	            // создать сертификат
	            return new Certificate(new ASN1.ISO.PKIX.Certificate(
                    tbsCertificate, signParameters, signature).Encoded
                ); 
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Создать сертификат X.509 по запросу PKCS10
		///////////////////////////////////////////////////////////////////////
        public static Certificate CreateCertificate(
            Factory factory, SecurityStore scope, IRand rand, 
            CertificateRequest certificateRequest, ASN1.IEncodable issuer, 
			ASN1.Integer serial, DateTime notBefore, DateTime notAfter, 
			ASN1.ISO.AlgorithmIdentifier signParameters, IPrivateKey privateKey, 
            ASN1.ISO.PKIX.CE.AuthorityKeyIdentifier authorityKeyIdentifier)
		{
            // извлечь запрос на сертификат
			ASN1.ISO.PKCS.PKCS10.CertificationRequest certificationRequest = 
				new ASN1.ISO.PKCS.PKCS10.CertificationRequest(
					ASN1.Encodable.Decode(certificateRequest.Encoded)
			); 
			// извлечь содержимое запроса на сертификат
			ASN1.ISO.PKCS.PKCS10.CertificationRequestInfo certificationRequestInfo = 
				certificationRequest.CertificationRequestInfo; 

			// извлечь данные для подписи
			byte[] tbsData = certificationRequestInfo.Encoded; 

			// извлечь описание открытого ключа
			ASN1.ISO.PKIX.SubjectPublicKeyInfo subjectPublicKeyInfo = 
				certificationRequestInfo.SubjectPKInfo; 

			// раскодировать открытый ключ
			IPublicKey publicKey = factory.DecodePublicKey(subjectPublicKeyInfo);

			// при ошибке выбросить исключение
			if (publicKey == null) throw new NotSupportedException();

			// создать алгоритм подписи
			using (VerifyData verifyAlgorithm = factory.CreateAlgorithm<VerifyData>(
				scope, certificationRequest.SignatureAlgorithm))
            {  
			    // при ошибке выбросить исключение
			    if (verifyAlgorithm == null) throw new NotSupportedException();

		        // обработать данные
		        verifyAlgorithm.Init(publicKey, certificationRequest.Signature.Value); 
			
		        // проверить подпись данных
		        verifyAlgorithm.Update(tbsData, 0, tbsData.Length); verifyAlgorithm.Finish();
            }
			// создать пустой список расширений
			List<ASN1.ISO.PKIX.Extension> listExtensions = new List<ASN1.ISO.PKIX.Extension>(); 

            // создать алгоритм хэширования SHA-1
            using (Hash hashAlgorithm = new ANSI.Hash.SHA1())
            {
                // закодировать открытый ключ
                ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = publicKey.Encoded; 

                // извлечь данные для хэширования
                byte[] publicKeyBits = publicKeyInfo.Content; 

                // вычислить хэш-значение
                ASN1.OctetString keyIdentifier = new ASN1.OctetString(
                    hashAlgorithm.HashData(publicKeyBits, 1, publicKeyBits.Length - 1)
                );
                // указать серийный номер сертификата
                if (serial == null) serial = new ASN1.Integer(
                    new Math.BigInteger(1, keyIdentifier.Value)
                ); 
                // добавить расширение
                listExtensions.Add(new ASN1.ISO.PKIX.Extension(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKIX.OID.ce_subjectKeyIdentifier), 
                    ASN1.Boolean.False, keyIdentifier
                ));
            }
            // при наличии идентификатора ключа в сертификате
            if (authorityKeyIdentifier != null)
            {
                // добавить расширение
                listExtensions.Add(new ASN1.ISO.PKIX.Extension(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKIX.OID.ce_authorityKeyIdentifier), 
                    ASN1.Boolean.False, authorityKeyIdentifier
                ));
            }
			// для всех атрибутов запроса на сертификат
			foreach (ASN1.ISO.Attribute attribute in certificationRequestInfo.Attributes)
			{
				// проверить идентификатор атрибута
				if (attribute.Type.Value == ASN1.ISO.PKCS.PKCS9.OID.extensionRequest)
				{
					// извлечь расширения для сертификата
					ASN1.ISO.PKIX.Extensions extensions = new ASN1.ISO.PKIX.Extensions(attribute); 

                    // добавить расширения в список
                    listExtensions.AddRange(extensions); break; 
				}
			}
            // создать сертификат
            return CreateCertificate(rand, issuer, serial, 
                certificationRequestInfo.Subject, subjectPublicKeyInfo, notBefore, 
                notAfter, signParameters, privateKey, listExtensions.ToArray()
            ); 
		}
	    ///////////////////////////////////////////////////////////////////////
	    // Проверить подпись сертификата
	    ///////////////////////////////////////////////////////////////////////
	    public static void VerifyCertificate(Factory factory, 
            SecurityStore scope, Certificate certificate, Certificate certificateCA) 
        {
		    // извлечь закодированный сертификат
		    ASN1.ISO.PKIX.Certificate decoded = certificate.Decoded; 
        
            // извлечь подписываемую часть
            ASN1.ISO.PKIX.TBSCertificate tbsCertificate = decoded.TBSCertificate; 
        
            // проверить соответствие издателя
            if (!tbsCertificate.Issuer.Equals(certificateCA.Subject)) 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException();
            }
            // найти расширение номера ключа издателя
            ASN1.OctetString authorityKeyIdentifier = certificate.IssuerKeyIdentifier; 
            
            // найти расширение номера субъекта
            ASN1.OctetString subjectKeyIdentifierCA = certificateCA.SubjectKeyIdentifier; 
            
            // при наличии расширений
            if (authorityKeyIdentifier != null && subjectKeyIdentifierCA != null)
            {
                // проверить совпадение номеров
                if (!Arrays.Equals(authorityKeyIdentifier.Value, subjectKeyIdentifierCA.Value))
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException();
                }
            }
            // раскодировать открытый ключ издателя
		    IPublicKey publicKeyCA = certificateCA.GetPublicKey(factory);
        
            // проверить подпись сертификата
            VerifyCertificate(factory, scope, certificate, publicKeyCA); 
        }
	    public static void VerifyCertificate(Factory factory, 
            SecurityStore scope, Certificate certificate, IPublicKey publicKeyCA) 
        {
		    // извлечь закодированный сертификат
		    ASN1.ISO.PKIX.Certificate decoded = certificate.Decoded; 
        
		    // извлечь данные для подписи
		    byte[] tbsData = decoded.TBSCertificate.Encoded; 

		    // создать алгоритм подписи
		    using (VerifyData verifyAlgorithm = 
                factory.CreateAlgorithm<VerifyData>(scope, decoded.SignatureAlgorithm))
            {
                // при ошибке выбросить исключение
                if (verifyAlgorithm == null) throw new NotSupportedException();
            
                // обработать данные
                verifyAlgorithm.Init(publicKeyCA, decoded.Signature.Value); 
			
                // проверить подпись данных
                verifyAlgorithm.Update(tbsData, 0, tbsData.Length); verifyAlgorithm.Finish();
            }
        }
		///////////////////////////////////////////////////////////////////////
		// Создать самоподписанный сертификат X.509
		///////////////////////////////////////////////////////////////////////
		public static Certificate CreateSelfSignedCertificate(
			IRand rand, ASN1.IEncodable subject, ASN1.ISO.AlgorithmIdentifier signParameters, 
            IPublicKey publicKey, IPrivateKey privateKey, 
            DateTime notBefore, DateTime notAfter, ASN1.ISO.PKIX.Extensions extensions)
        {
			// создать запрос на сертификат
			CertificateRequest certificateRequest = CreateCertificationRequest( 
				rand, subject, signParameters, publicKey, privateKey, extensions
			);
            // закодировать открытый ключ
            ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = publicKey.Encoded; 

            // создать алгоритм хэширования SHA-1
            using (Hash hashAlgorithm = new ANSI.Hash.SHA1())
            {
                // извлечь данные для хэширования
                byte[] publicKeyBits = publicKeyInfo.Content; 

                // вычислить хэш-значение
                ASN1.OctetString keyIdentifier = new ASN1.OctetString(
                    hashAlgorithm.HashData(publicKeyBits, 1, publicKeyBits.Length - 1)
                ); 
                // указать серийный номер сертификата
                ASN1.Integer serial = new ASN1.Integer(
                    new Math.BigInteger(1, keyIdentifier.Value)
                ); 
                // указать имя издателя
                ASN1.ISO.PKIX.GeneralNames issuer = new ASN1.ISO.PKIX.GeneralNames(
                    new ASN1.IEncodable[] { ASN1.Explicit.Encode(ASN1.Tag.Context(4), subject) });

                // создать идентификатор ключа
                ASN1.ISO.PKIX.CE.AuthorityKeyIdentifier authorityKeyIdentifier = 
                    new ASN1.ISO.PKIX.CE.AuthorityKeyIdentifier(
                        keyIdentifier, issuer, new ASN1.Integer(serial)
                );
                // создать самоподписанный сертификат
                return CreateCertificate(privateKey.Factory, privateKey.Scope, rand,   
                    certificateRequest, subject, serial, notBefore, notAfter, 
                    certificateRequest.SignatureAlgorithm, privateKey, authorityKeyIdentifier
			    );
            }
        }
		public static Certificate CreateSelfSignedCertificate(
			IRand rand, ASN1.IEncodable subject, ASN1.ISO.AlgorithmIdentifier signParameters, 
            IPublicKey publicKey, IPrivateKey privateKey, 
            DateTime notBefore, DateTime notAfter, KeyUsage keyUsage, String[] extKeyUsage, 
            ASN1.ISO.PKIX.CE.BasicConstraints basicConstraints, 
            ASN1.ISO.PKIX.CE.CertificatePolicies policies, ASN1.ISO.PKIX.Extensions extensions)
		{
            // объединить расширения
            extensions = AddExtensions(extensions, keyUsage, extKeyUsage, basicConstraints, policies); 

            // создать самоподписанный сертификат
            return CreateSelfSignedCertificate(rand, subject, signParameters, 
                publicKey, privateKey, notBefore, notAfter, extensions
            ); 
		}
	}
}
