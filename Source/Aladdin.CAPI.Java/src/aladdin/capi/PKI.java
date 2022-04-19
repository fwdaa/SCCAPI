package aladdin.capi;
import aladdin.asn1.*; 
import aladdin.asn1.Boolean; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkix.ce.*; 
import aladdin.asn1.iso.pkcs.pkcs10.*; 
import java.security.*; 
import java.math.*; 
import java.io.*; 
import java.util.*; 

public abstract class PKI
{
	///////////////////////////////////////////////////////////////////////
	// Признак самоподписанного сертификата
	///////////////////////////////////////////////////////////////////////
    public static boolean isSelfSignedCertificate(Certificate certificate)
    {
        // признак самоподписанного сертификата
        return isIssuedByCA(certificate, certificate); 
    }
    private static boolean isIssuedByCA(Certificate certificate, Certificate parent)
    {
        // проверить совпадение издателя
        if (!parent.issuer().equals(certificate.subject())) return false; 

        // найти расширение номера ключа издателя
        OctetString authorityKeyIdentifier = certificate.issuerKeyIdentifier(); 
            
        // найти расширение номера субъекта
        OctetString subjectKeyIdentifierCA = parent.subjectKeyIdentifier(); 
            
        // при наличии расширений
        if (authorityKeyIdentifier != null && subjectKeyIdentifierCA != null)
        {
            // проверить совпадение номеров
            if (!authorityKeyIdentifier.equals(subjectKeyIdentifierCA)) return false; 
        }
        return true; 
    }
	///////////////////////////////////////////////////////////////////////
	// Создать цепочку сертификатов
	///////////////////////////////////////////////////////////////////////
    public static Certificate[] createCertificateChain(
        Certificate certificate, Iterable<Certificate> certificates)
    {
        // инициализировать цепочку сертификатов
        List<Certificate> certificateChain = new ArrayList<Certificate>(); 
        
        // добавить исходный сертификат
        certificateChain.add(certificate); 
        
        // до появления самоподписанного сертификата
        while (!isSelfSignedCertificate(certificate))
        {
            // сохранить текущий сертификат
            Certificate current = certificate; 

            // для всех сертификатов
            for (Certificate parent : certificates)
            {
                // проверить нахождение издателя
                if (!isIssuedByCA(certificate, parent)) continue; 

                // добавить сертификат издателя в список
                certificateChain.add(parent); certificate = parent; break; 
            }
            // проверить успешность поиска
            if (current == certificate) break; 
        }
        // вернуть цепочку сертификатов
        return certificateChain.toArray(new Certificate[certificateChain.size()]); 
    }
	///////////////////////////////////////////////////////////////////////
	// Объединить расширения
	///////////////////////////////////////////////////////////////////////
    public static Extensions addExtensions(Extensions extensions, 
        KeyUsage keyUsage, String[] extKeyUsage, 
        BasicConstraints basicConstraints, CertificatePolicies policies)
    {
        // создать список расширений
        List<Extension> listExtensions = new ArrayList<Extension>(); 

        // при указании использования ключа
        if (!keyUsage.isEmpty())
        {
            // добавить расширение
            listExtensions.add(new Extension(
                new ObjectIdentifier(OID.CE_KEY_USAGE), 
				Boolean.TRUE, new BitFlags(keyUsage.value())
            ));
        }
        // при указании использования ключа
        if (extKeyUsage != null && extKeyUsage.length != 0) 
        { 
            // создать список идентификаторов
            ObjectIdentifier[] oids = new ObjectIdentifier[extKeyUsage.length]; 

            // указать признак критичности
            Boolean critical = Boolean.TRUE; 

            // для всех идентификаторов
            for (int i = 0; i < extKeyUsage.length; i++)
            {
                // скорректировать признак критичности
                if (extKeyUsage[i].equals(OID.CE_EXT_KEY_USAGE_ANY)) critical = Boolean.FALSE; 

                // закодировать идентификатор
                oids[i] = new ObjectIdentifier(extKeyUsage[i]); 
            }
            // добавить расширение
            listExtensions.add(new Extension(
                new ObjectIdentifier(OID.CE_EXT_KEY_USAGE), 
			    critical, new ExtKeyUsageSyntax(oids)
            ));
        }
        // при наличии расширения
        if (basicConstraints != null)
        {
            // добавить расширение
            listExtensions.add(new Extension(
                new ObjectIdentifier(OID.CE_BASIC_CONSTRAINTS), 
                Boolean.TRUE, basicConstraints
            ));
        }
        // при наличии политик
        if (policies != null && policies.size() > 0)
        {
            // добавить расширение
            listExtensions.add(new Extension(
                new ObjectIdentifier(OID.CE_CERIFICATE_POLICIES), 
                Boolean.TRUE, policies
            ));
        }
        // при наличии расширений
        if (extensions != null && extensions.size() > 0) 
        { 
            // для всех расширений
            for (Extension extension : extensions)
            {
                // добавить расширение в список
                listExtensions.add(extension); 
            }
        }
        // проверить наличие расширений
        if (listExtensions.isEmpty()) return null; 

        // объединить расширения
        return new Extensions(listExtensions.toArray(new Extension[0])); 
    }
	///////////////////////////////////////////////////////////////////////
	// Создать запрос PKCS10 на сертификат X.509
	///////////////////////////////////////////////////////////////////////
    public static CertificateRequest createCertificationRequest(IRand rand, 
        IEncodable subject, AlgorithmIdentifier signParameters, 
        IPublicKey publicKey, IPrivateKey privateKey, Extensions extensions) throws IOException
    {
        // закодировать открытый ключ
        SubjectPublicKeyInfo publicKeyInfo = publicKey.encoded(); 
        
        // создать список расширений
        List<Extension> listExtensions = new ArrayList<Extension>(); 

        // при наличии расширений
        if (extensions != null && extensions.size() > 0) 
        { 
            // для всех расширений
            for (Extension extension : extensions)
            {
                // проверить допустимость расширения
                if (!extension.extnID().value().equals(OID.CE_SUBJECT_KEY_IDENTIFIER) && 
                    !extension.extnID().value().equals(OID.CE_AUTHORITY_KEY_IDENTIFIER) &&
                    !extension.extnID().value().equals(OID.CE_AUTHORITY_KEY_IDENTIFIER_OLD))
                {
                    // добавить расширение в список
                    listExtensions.add(extension); 
                }
            }
        }
        // создать значение атрибута
	    aladdin.asn1.Set<Extensions> attributeValue = 
		    new aladdin.asn1.Set<Extensions>(Extensions.class, new Extensions[] { 
                new Extensions(listExtensions.toArray(new Extension[0]))
        });
        // создать атрибут запроса на сертификат
        Attribute attribute = new Attribute(new ObjectIdentifier(
            aladdin.asn1.iso.pkcs.pkcs9.OID.EXTENSION_REQUEST), attributeValue
        ); 
        // создать множество атрибутов
        Attributes attributes = new Attributes(new Attribute[] {attribute}); 
        
		// создать запрос на сертификат
		CertificationRequestInfo certificationRequestInfo = 
			new CertificationRequestInfo(
				new Integer(0), subject, publicKeyInfo, attributes
		); 
		// извлечь подписываемые данные
		byte[] data = certificationRequestInfo.encoded(); 
        
        // при отсутствии алгоритма
        if (signParameters.algorithm().value().equals("2.5.8.0"))
        {
            // создать пустую подпись
            BitString signature = new BitString(new byte[0]); 
            
            // создать запрос на сертификат
            aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest request = 
                new aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest(
                    certificationRequestInfo, signParameters, signature
            ); 
            // вернуть запрос на сертификат
            return new CertificateRequest(request);
        }
        // создать алгоритм подписи
        try (SignData signAlgorithm = (SignData)privateKey.factory().createAlgorithm(
            privateKey.scope(), signParameters, SignData.class))
        {
            // при ошибке выбросить исключение
            if (signAlgorithm == null) throw new UnsupportedOperationException();

            // вычислить подпись данных
            BitString signature = new BitString(signAlgorithm.sign(
                privateKey, rand, data, 0, data.length
            )); 
            // создать запрос на сертификат
            aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest request = 
                new aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest(
                    certificationRequestInfo, signParameters, signature
            ); 
            // вернуть запрос на сертификат
            return new CertificateRequest(request);
        }
    }
    public static CertificateRequest createCertificationRequest(IRand rand, 
        IEncodable subject, AlgorithmIdentifier signParameters, 
        IPublicKey publicKey, IPrivateKey privateKey, 
        KeyUsage keyUsage, String[] extKeyUsage, 
        BasicConstraints basicConstraints, CertificatePolicies policies, 
        Extensions extensions) throws IOException
	{
        // объединить расширения
        extensions = addExtensions(
            extensions, keyUsage, extKeyUsage, basicConstraints, policies
        ); 
        // создать запрос на сертификат
        return createCertificationRequest(rand, 
            subject, signParameters, publicKey, privateKey, extensions
        ); 
	}
	///////////////////////////////////////////////////////////////////////
	// Создать сертификат X.509
	///////////////////////////////////////////////////////////////////////
	public static Certificate createCertificate(IRand rand, IEncodable issuer, 
        Integer serial, IEncodable subject, SubjectPublicKeyInfo publicKeyInfo, 
        Date notBefore, Date notAfter, AlgorithmIdentifier signParameters, 
        IPrivateKey privateKey, Extension[] extensions) throws IOException
	{
        // указать значения по умолчанию
        Extensions exts = null; Integer version = new Integer(0);

        // при наличии расширений
        if (extensions != null && extensions.length > 0) 
        { 
            // объединить расширения
            exts = new Extensions(extensions); version = new Integer(2); 
        }
		// закодировать срок действия
		GeneralizedTime encodedNotBefore = new GeneralizedTime(notBefore); 
		GeneralizedTime encodedNotAfter  = new GeneralizedTime(notAfter ); 

		// создать описание срока действия
		Validity validity = new Validity(encodedNotBefore, encodedNotAfter); 
        
		// создать информацию сертификата
		TBSCertificate tbsCertificate = new TBSCertificate(
            version, serial, signParameters, issuer, 
            validity, subject, publicKeyInfo, null, null, exts
		); 
		// извлечь подписываемые данные
		byte[] data = tbsCertificate.encoded(); 
        
		// создать алгоритм подписи
		try (SignData signAlgorithm = (SignData)privateKey.factory().createAlgorithm(
            privateKey.scope(), signParameters, SignData.class))
        {
            // при ошибке выбросить исключение
            if (signAlgorithm == null) throw new  UnsupportedOperationException();
            
            // вычислить подпись данных
            BitString signature = new BitString(signAlgorithm.sign(
                privateKey, rand, data, 0, data.length
            )); 
            // создать сертификат
            return new Certificate(new aladdin.asn1.iso.pkix.Certificate(
                tbsCertificate, signParameters, signature
            )); 
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Создать сертификат X.509 по запросу PKCS10
	///////////////////////////////////////////////////////////////////////
	public static Certificate createCertificate(Factory factory, 
        SecurityStore scope, IRand rand, CertificateRequest certificateRequest, 
        IEncodable issuer, Integer serial, Date notBefore, 
        Date notAfter, AlgorithmIdentifier signParameters, 
        IPrivateKey privateKey, AuthorityKeyIdentifier authorityKeyIdentifier) 
        throws SignatureException, IOException
	{
		// извлечь запрос на сертификат
		aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest 
            certificationRequest = certificateRequest.decoded(); 
        
		// извлечь содержимое запроса на сертификат
		CertificationRequestInfo certificationRequestInfo = 
			certificationRequest.certificationRequestInfo(); 

		// извлечь данные для подписи
		byte[] tbsData = certificationRequestInfo.encoded(); 

		// извлечь описание открытого ключа
		SubjectPublicKeyInfo subjectPublicKeyInfo = 
			certificationRequestInfo.subjectPKInfo(); 

        // раскодировать открытый ключ
		IPublicKey publicKey = factory.decodePublicKey(subjectPublicKeyInfo);
        
		// при ошибке выбросить исключение
		if (publicKey == null) throw new UnsupportedOperationException();

		// создать алгоритм подписи
		try (VerifyData verifyAlgorithm = (VerifyData)factory.createAlgorithm(
            scope, certificationRequest.signatureAlgorithm(), VerifyData.class))
        {
            // при ошибке выбросить исключение
            if (verifyAlgorithm == null) throw new UnsupportedOperationException();
            
            // обработать данные
            verifyAlgorithm.init(publicKey, certificationRequest.signature().value()); 
			
            // проверить подпись данных
            verifyAlgorithm.update(tbsData, 0, tbsData.length); verifyAlgorithm.finish();
        }
		// создать пустой список расширений
		List<Extension> listExtensions = new ArrayList<Extension>(); 

        // создать алгоритм хэширования SHA-1
        try (Hash hashAlgorithm = new aladdin.capi.ansi.hash.SHA1())
        {
            // закодировать открытый ключ
            SubjectPublicKeyInfo publicKeyInfo = publicKey.encoded(); 
            
            // извлечь данные для хэширования
            byte[] publicKeyBits = publicKeyInfo.content(); 

            // вычислить хэш-значение
            OctetString keyIdentifier = new OctetString(
                hashAlgorithm.hashData(publicKeyBits, 1, publicKeyBits.length - 1)
            ); 
            // указать серийный номер сертификата
            if (serial == null) serial = new Integer(new BigInteger(1, keyIdentifier.value())); 
            
            // добавить расширение
            listExtensions.add(new Extension(
                new ObjectIdentifier(aladdin.asn1.iso.pkix.OID.CE_SUBJECT_KEY_IDENTIFIER), 
                Boolean.FALSE, keyIdentifier
            ));
        }
        // при наличии идентификатора ключа в сертификате
        if (authorityKeyIdentifier != null)
        {
            // добавить расширение
            listExtensions.add(new Extension(
                new ObjectIdentifier(aladdin.asn1.iso.pkix.OID.CE_AUTHORITY_KEY_IDENTIFIER), 
                Boolean.FALSE, authorityKeyIdentifier
            ));
        }
        // для всех атрибутов запроса на сертификат
		for (Attribute attribute : certificationRequestInfo.attributes())
		{
			// проверить идентификатор атрибута
			if (attribute.type().value().equals(aladdin.asn1.iso.pkcs.pkcs9.OID.EXTENSION_REQUEST))
			{
				// извлечь расширения для сертификата
				Extensions extensions = new Extensions(attribute); 

                // добавить расширения в список
                for (Extension extension : extensions) listExtensions.add(extension); break; 
            }
        }
        // создать сертификат
        return createCertificate(rand, issuer, serial, 
            certificationRequestInfo.subject(), subjectPublicKeyInfo, 
            notBefore, notAfter, signParameters, 
            privateKey, listExtensions.toArray(new Extension[0])
        ); 
	}
	///////////////////////////////////////////////////////////////////////
	// Проверить подпись сертификата
	///////////////////////////////////////////////////////////////////////
	public static void verifyCertificate(Factory factory, 
        SecurityStore scope, Certificate certificate, Certificate certificateCA) 
        throws SignatureException, IOException
    {
        // проверить соответствие издателя
        if (!isIssuedByCA(certificate, certificateCA)) throw new IOException();
        
        // раскодировать открытый ключ издателя
		IPublicKey publicKeyCA = certificateCA.getPublicKey(factory);
        
        // проверить подпись сертификата
        verifyCertificate(factory, scope, certificate, publicKeyCA); 
    }
	public static void verifyCertificate(Factory factory, 
        SecurityStore scope, Certificate certificate, IPublicKey publicKeyCA) 
        throws SignatureException, IOException
    {
		// извлечь закодированный сертификат
		aladdin.asn1.iso.pkix.Certificate decoded = certificate.decoded(); 
        
		// извлечь данные для подписи
		byte[] tbsData = decoded.tbsCertificate().encoded(); 

		// создать алгоритм подписи
		try (VerifyData verifyAlgorithm = (VerifyData)factory.createAlgorithm(
            scope, decoded.signatureAlgorithm(), VerifyData.class))
        {
            // при ошибке выбросить исключение
            if (verifyAlgorithm == null) throw new UnsupportedOperationException();
            
            // обработать данные
            verifyAlgorithm.init(publicKeyCA, decoded.signature().value()); 
			
            // проверить подпись данных
            verifyAlgorithm.update(tbsData, 0, tbsData.length); verifyAlgorithm.finish();
        }
    }
	///////////////////////////////////////////////////////////////////////
	// Создать самоподписанный сертификат X.509
	///////////////////////////////////////////////////////////////////////
	public static Certificate createSelfSignedCertificate(IRand rand, 
        IEncodable subject, AlgorithmIdentifier signParameters, 
        IPublicKey publicKey, IPrivateKey privateKey, 
        Date notBefore, Date notAfter, Extensions extensions) throws IOException
    {
		// создать запрос на сертификат
		CertificateRequest certificateRequest = createCertificationRequest(
            rand, subject, signParameters, publicKey, privateKey, extensions
		);
        // закодировать открытый ключ
        SubjectPublicKeyInfo publicKeyInfo = publicKey.encoded(); 
        
        // создать алгоритм хэширования SHA-1
        try (Hash hashAlgorithm = new aladdin.capi.ansi.hash.SHA1())
        {
            // извлечь данные для хэширования
            byte[] publicKeyBits = publicKeyInfo.content(); 

            // вычислить хэш-значение
            OctetString keyIdentifier = new OctetString(
                hashAlgorithm.hashData(publicKeyBits, 1, publicKeyBits.length - 1)
            ); 
            // указать серийный номер сертификата
            Integer serial = new Integer(new BigInteger(1, keyIdentifier.value())); 
            
            // указать имя издателя
            GeneralNames issuer = new GeneralNames(new IEncodable[] {
                Explicit.encode(Tag.context(4), subject)
            });
            // создать идентификатор ключа
            AuthorityKeyIdentifier authorityKeyIdentifier = 
                new AuthorityKeyIdentifier(keyIdentifier, issuer, serial); 
            try {
                // создать самоподписанный сертификат
                return createCertificate(privateKey.factory(), privateKey.scope(), rand,  
                    certificateRequest, subject, serial, notBefore, notAfter, 
                    certificateRequest.signatureAlgorithm(), privateKey, authorityKeyIdentifier
                ); 
            }
            // обработать неожидаемое исключение
            catch (SignatureException e) { throw new RuntimeException(e); }
        }
    }
	public static Certificate createSelfSignedCertificate(IRand rand, 
        IEncodable subject, AlgorithmIdentifier signParameters, 
        IPublicKey publicKey, IPrivateKey privateKey, 
        Date notBefore, Date notAfter, KeyUsage keyUsage, 
        String[] extKeyUsage, BasicConstraints basicConstraints, 
        CertificatePolicies policies, Extensions extensions) throws IOException
	{
        // объединить расширения
        extensions = addExtensions(extensions, keyUsage, extKeyUsage, basicConstraints, policies); 
        
        // создать самоподписанный сертификат
        return createSelfSignedCertificate(rand, subject, 
            signParameters, publicKey, privateKey, notBefore, notAfter, extensions
        ); 
	}
}
