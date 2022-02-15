package aladdin.capi;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkix.ce.*; 
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.math.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Сертификат X509
///////////////////////////////////////////////////////////////////////////
public class Certificate extends java.security.cert.X509Certificate
{
    // номер версии для сериализации
    private static final long serialVersionUID = 6507987451672408068L;

    ///////////////////////////////////////////////////////////////////////
	// Конструкторы
	///////////////////////////////////////////////////////////////////////
	public Certificate(InputStream stream) throws IOException
    {
        // прочитать первый символ
        int first = stream.read(); if (first < 0) throw new IOException(); 
        
        // для PEM-кодировки
        if (first == 0x2D) { byte[] encoded = PEM.decode(stream, (byte)first);
        
            // раскодировать сертификат
            IEncodable encodable = Encodable.decode(encoded); 
        
            // сохранить содержимое сертификата
            this.certificate = new aladdin.asn1.iso.pkix.Certificate(encodable); 
        }
        else {
            // раскодировать сертификат
            IEncodable encodable = Encodable.decode(stream, (byte)first); 
        
            // сохранить содержимое сертификата
            this.certificate = new aladdin.asn1.iso.pkix.Certificate(encodable); 
        }
    }
	public Certificate(byte[] encoded) throws IOException
    {
        // обработать PEM-кодировку
        if (encoded.length != 0 && encoded[0] == 0x2D) encoded = PEM.decode(encoded);
        
        // раскодировать сертификат
        IEncodable encodable = Encodable.decode(encoded); 
        
        // сохранить содержимое сертификата
        this.certificate = new aladdin.asn1.iso.pkix.Certificate(encodable); 
    }
	public Certificate(aladdin.asn1.iso.pkix.Certificate certificate)
    {
        // сохранить содержимое сертификата
        this.certificate = certificate; 
    }
    // раскодированный сертификат
    private final aladdin.asn1.iso.pkix.Certificate certificate;   
    
    // раскодированный сертификат
    public aladdin.asn1.iso.pkix.Certificate decoded() { return certificate; }
    
    ///////////////////////////////////////////////////////////////////////
    // Закодированное представление
	///////////////////////////////////////////////////////////////////////
    public byte[] der() { return certificate.encoded(); }
    public String pem()  
    {
        // закодировать сертификат
        return PEM.encode(getEncoded(), "CERTIFICATE"); 
    }
    // закодированное представление 
    @Override public byte[] getEncoded() { return certificate.encoded(); }
    
	///////////////////////////////////////////////////////////////////////
	// Строковое представление
	///////////////////////////////////////////////////////////////////////
    @Override public String toString()
    {
        /* TODO */ return null; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Подпись сертификата
    ///////////////////////////////////////////////////////////////////////
    @Override public byte[] getTBSCertificate()
    {
        // подписываемая часть сертификата
        return certificate.tbsCertificate().encoded(); 
    }
	public AlgorithmIdentifier signatureAlgorithm() 
    { 
        // описание алгоритма подписи
        return certificate.signatureAlgorithm();    
    }
    // идентификатор алгоритма подписи
    @Override public String getSigAlgName() { return getSigAlgOID(); }
    @Override public String getSigAlgOID ()
    {
        // получить описание алгоритма подписи
        AlgorithmIdentifier algorithm = signatureAlgorithm(); 
        
        // идентификатор алгоритма подписи
        return algorithm.algorithm().value(); 
    }
    @Override public byte[] getSigAlgParams()
    {
        // получить описание алгоритма подписи
        AlgorithmIdentifier algorithm = signatureAlgorithm(); 
        
        // проверить наличие параметров
        if (algorithm.parameters() == null) return null; 
        
        // вернуть параметры алгоритма подписи
        return algorithm.parameters().encoded(); 
    }
    @Override public byte[] getSignature()
    {
        // подпись сертификата
        return signature().value(); 
    }
    // подпись сертификата
	public BitString signature() { return certificate.signature(); }
    
	///////////////////////////////////////////////////////////////////////
	// Открытый ключ сертификата
	///////////////////////////////////////////////////////////////////////
    static class PublicKey implements java.security.PublicKey
    {
        // номер версии для сериализации
        private static final long serialVersionUID = -6688733610573753855L;
        
        // закодированное представление
        private final SubjectPublicKeyInfo publicKeyInfo; 
        
        // конструктор
        public PublicKey(SubjectPublicKeyInfo publicKeyInfo)
        {
            // сохранить переданные параметры
            this.publicKeyInfo = publicKeyInfo; 
        }
        // идентификатор алгоритма ключа
        @Override public String getAlgorithm() 
        { 
            // идентификатор алгоритма ключа
            return publicKeyInfo.algorithm().algorithm().value(); 
        }  
        // формат закодированного представления
        @Override public String getFormat() { return "X.509"; }
    
        // закодированное представление
        @Override public byte[] getEncoded() { return publicKeyInfo.encoded(); }
    }
    // открытый ключ сертификата
	public IPublicKey getPublicKey(Factory factory) throws IOException
    { 
        // раскодировать открытый ключ
        return factory.decodePublicKey(publicKeyInfo()); 
    }
    // открытый ключ сертификата
    @Override public java.security.PublicKey getPublicKey()
    {
        // открытый ключ сертификата
        return new PublicKey(publicKeyInfo()); 
    }
	public SubjectPublicKeyInfo	publicKeyInfo() 
    { 
        // закодированный открытый ключ сертификата
        return certificate.tbsCertificate().subjectPublicKeyInfo();         
    }
    ///////////////////////////////////////////////////////////////////////
    // Атрибуты сертификата
    ///////////////////////////////////////////////////////////////////////
    @Override public int getVersion()
    {
        // версия сертификата
        return certificate.tbsCertificate().version().value().intValue(); 
    }
    // издатель сертификата
	public IEncodable issuer() { return certificate.tbsCertificate().issuer(); }

    // издатель сертификата
    @Override public java.security.Principal getIssuerDN() 
    { 
        try { 
            // получить описание метода
            java.lang.reflect.Method method = getClass().getMethod("getIssuerX500Principal");
            
            // вызвать метод
            return (java.security.Principal)method.invoke(this); 
        } 
        // обработать возможную ошибку
        catch (Throwable e) { return new Principal(issuer()); }
    }
    // получить уникальный идентификатор издателя
    @Override public boolean[] getIssuerUniqueID()
    {
        // получить уникальный идентификатор издателя
        BitString uniqueID = certificate.tbsCertificate().issuerUniqueID(); 
        
        // проверить наличие уникального идентификатора
        if (uniqueID == null) return null; 
        
        // выделить память для результата
        boolean[] result = new boolean[uniqueID.bits()]; 
        
        // получить значение идентификатора
        byte[] value = uniqueID.value(); int mask = 0x80; 
        
        // для всех битов
        for (int i = 0; i < result.length; i++)
        {
            // извлечь отдельный бит
            result[i] = (value[i / 8] & mask) != 0; 
            
            // сдвинуть используемую маску
            mask = (mask != 1) ? (mask >>> 1) : 0x80; 
        }
        return result; 
    }
    @Override public BigInteger getSerialNumber()
    {
        // серийный номер сертификата
        return certificate.tbsCertificate().serialNumber().value(); 
    }
    public IssuerSerialNumber issuerSerialNumber() 
    { 
        // издатель и серийный номер сертификата
        return certificate.tbsCertificate().issuerSerialNumber();           
    }
    // идентификатор ключа издателя
    public OctetString issuerKeyIdentifier () 
    { 
        // получить расширения сертификата
        Extensions extensions = extensions(); if (extensions == null) return null;
        try { 
            // получить требуемое расширение
            AuthorityKeyIdentifier extension = extensions.authorityKeyIdentifier(); 
            
            // вернуть идентификатор ключа издателя
            return (extension != null) ? extension.keyIdentifier() : null; 
        }
        // обработать возможную ошибку
        catch (Throwable e) { e.printStackTrace(); return null; }
    }
    // субъект сертификата
	public IEncodable subject() { return certificate.tbsCertificate().subject(); }
    
    // субъект сертификата
    @Override public java.security.Principal getSubjectDN() 
    { 
        try { 
            // получить описание метода
            java.lang.reflect.Method method = getClass().getMethod("getSubjectX500Principal");
            
            // вызвать метод
            return (java.security.Principal)method.invoke(this); 
        } 
        // обработать возможную ошибку
        catch (Throwable e) { return new Principal(subject()); }
    }
    // получить уникальный идентификатор субъекта
    @Override public boolean[] getSubjectUniqueID()
    {
        // получить уникальный идентификатор субъекта
        BitString uniqueID = certificate.tbsCertificate().subjectUniqueID(); 
        
        // проверить наличие уникального идентификатора
        if (uniqueID == null) return null; 
        
        // выделить память для результата
        boolean[] result = new boolean[uniqueID.bits()]; 
        
        // получить значение идентификатора
        byte[] value = uniqueID.value(); int mask = 0x80; 
        
        // для всех битов
        for (int i = 0; i < result.length; i++)
        {
            // извлечь отдельный бит
            result[i] = (value[i / 8] & mask) != 0; 
            
            // сдвинуть используемую маску
            mask = (mask != 1) ? (mask >>> 1) : 0x80; 
        }
        return result; 
    }
    // идентификатор ключа субъекта
    public OctetString subjectKeyIdentifier() 
    { 
        // получить расширения сертификата
        Extensions extensions = extensions(); if (extensions == null) return null;
        try { 
            // вернуть идентификатор ключа субъекта
            return extensions.subjectKeyIdentifier(); 
        }
        // обработать возможную ошибку
        catch (Throwable e) { return null; }
    }
    ///////////////////////////////////////////////////////////////////////
    // Срок действия сертификата
    ///////////////////////////////////////////////////////////////////////
    @Override public Date getNotBefore()
    {
        // время начала действия сертификата
        return certificate.tbsCertificate().validity().notBeforeDate();
    }
    @Override public Date getNotAfter()
    {
        // время окончания действия сертификата
        return certificate.tbsCertificate().validity().notAfterDate(); 
    }
    // проверить срок действия сертификата
    @Override public void checkValidity(Date date)
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        // проверить срок действия сертификата
        if (date.before(getNotBefore()))
        {
            // выбросить исключение
            throw new CertificateNotYetValidException(); 
        }
        // проверить срок действия сертификата
        if (date.after(getNotAfter()))
        {
            // выбросить исключение
            throw new CertificateExpiredException(); 
        }
    }
    // проверить срок действия сертификата
    @Override public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        // проверить срок действия сертификата
        checkValidity(new Date()); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Расширения сертификата
    ///////////////////////////////////////////////////////////////////////
	public Extensions extensions() { return certificate.tbsCertificate().extensions(); }
    
    // признак наличия неподдерживаемых критичных расширений
    @Override public boolean hasUnsupportedCriticalExtension() { return false; }
    
    // идентификаторы критичных расширений
    @Override public java.util.Set<String> getCriticalExtensionOIDs()
    {
        // получить расширения сертификата
        Extensions extensions = extensions(); if (extensions == null) return null;
        
        // создать список идентификаторов криптических расширений
        java.util.Set<String> oids = new java.util.HashSet<String>();
        
        // для всех расширений сертификата
        for (aladdin.asn1.iso.pkix.Extension extension : extensions) 
        {
            // проверить критичность расширения
            if (!extension.critical().value()) continue; 
            
            // созранить идентификатор расширения
            oids.add(extension.extnID().value()); 
        }
        return oids; 
    }
    @Override public java.util.Set<String> getNonCriticalExtensionOIDs()
    {
        // получить расширения сертификата
        Extensions extensions = extensions(); if (extensions == null) return null;
        
        // создать список идентификаторов криптических расширений
        java.util.Set<String> oids = new java.util.HashSet<String>();
        
        // для всех расширений сертификата
        for (aladdin.asn1.iso.pkix.Extension extension : extensions) 
        {
            // проверить критичность расширения
            if (extension.critical().value()) continue; 
            
            // созранить идентификатор расширения
            oids.add(extension.extnID().value()); 
        }
        return oids; 
    }
    @Override public byte[] getExtensionValue(String oid)
    {
        // получить расширения сертификата
        Extensions extensions = extensions(); if (extensions == null) return null;
        
        // для всех расширений сертификата
        for (aladdin.asn1.iso.pkix.Extension extension : extensions) 
        {
            // проверить идентификатор расширения
            if (!extension.extnID().value().equals(oid)) continue; 
            
            // вернуть закодированное представление
            return new OctetString(extension.extnValue().encoded()).encoded(); 
        }
        return null; 
    }
    // способ использования ключа
    public KeyUsage keyUsage() 
    { 
        // получить расширения сертификата
        Extensions extensions = extensions(); if (extensions == null) return KeyUsage.NONE;
        try {    
            // вернуть способ использования ключа
            return new KeyUsage(extensions.keyUsage());             
        }
        // обработать возможную ошибку
        catch (Throwable e) { return KeyUsage.NONE; }
    }
    // способ использования ключа
    @Override public boolean[] getKeyUsage()
    {
        // получить расширения сертификата
        Extensions extensions = extensions(); if (extensions == null) return null;
        try {    
            // найти требуемое расширение
            IEncodable extension = extensions.get(OID.CE_KEY_USAGE); 

            // проверить наличие расширения
            if (extension == null) return null;
            
            // раскодировать расширение
            BitString keyUsage = new BitString(extension); 
            
            // выделить память для результата
            boolean[] result = new boolean[keyUsage.bits()]; 
        
            // получить значение расширения
            byte[] value = keyUsage.value(); int mask = 0x80; 
        
            // для всех битов
            for (int i = 0; i < result.length; i++)
            {
                // извлечь отдельный бит
                result[i] = (value[i / 8] & mask) != 0; 
            
                // сдвинуть используемую маску
                mask = (mask != 1) ? (mask >>> 1) : 0x80; 
            }
            return result; 
        }
        // обработать возможную ошибку
        catch (Throwable e) { return null; }
    }
    // расширенные способы использования ключа
    public String[] extendedKeyUsage() 
    { 
        // получить расширения сертификата
        Extensions extensions = extensions(); if (extensions == null) return null;
        try {    
            // получить расширенные способы использования ключа
            ExtKeyUsageSyntax extendedKeyUsage = extensions.extendedKeyUsage();  
            
            // проверить наличие расширенных способов
            if (extendedKeyUsage == null) return null; 
            
            // выделить память для результата
            String[] oids = new String[extendedKeyUsage.size()]; 
                
            // извлечь дополнительные назначения ключа
            for (int i = 0; i < oids.length; i++) 
            {
                oids[i] = extendedKeyUsage.get(i).value(); 
            }
            return oids;             
        }
        // обработать возможную ошибку
        catch (Throwable e) { return null; }
    }
    @Override public int getBasicConstraints()
    {
        // получить расширения сертификата
        Extensions extensions = extensions(); if (extensions == null) return -1;
        try {    
            // найти требуемое расширение
            IEncodable extension = extensions.get(OID.CE_BASIC_CONSTRAINTS); 

            // проверить наличие расширения
            if (extension == null) return -1;
            
            // раскодировать расширение
            BasicConstraints basicConstraints = new BasicConstraints(extension); 
            
            // проверить тип субъекта
            if (basicConstraints.ca() == null || !basicConstraints.ca().value()) return -1; 
            
            // проверить наличие ограничения на размер цепочки
            if (basicConstraints.pathLenConstraint() == null) 
            {
                return java.lang.Integer.MAX_VALUE; 
            }
            // вернуть максимальный размер цепочки
            return basicConstraints.pathLenConstraint().value().intValue(); 
        }
        // обработать возможную ошибку
        catch (Throwable e) { return -1; }
    }
    ///////////////////////////////////////////////////////////////////////
    // Проверка корректности сертификата
    ///////////////////////////////////////////////////////////////////////
    @Override public void verify(java.security.PublicKey publicKey)
        throws InvalidKeyException, SignatureException, NoSuchAlgorithmException
    {
        // получить данные для проверки 
        byte[] data = getTBSCertificate(); byte[] signature = getSignature();
        
        // указать алгоритм подписи
        Signature algorithm = Signature.getInstance(getSigAlgName());

        // инициализировать алгоритм и обработать данные
        algorithm.initVerify(publicKey); algorithm.update(data, 0, data.length);
            
        // проверить подпись
        if (!algorithm.verify(signature)) throw new SignatureException();
    }
    @Override public void verify(java.security.PublicKey publicKey, String provider)
        throws InvalidKeyException, SignatureException, 
            NoSuchProviderException, NoSuchAlgorithmException
    {
        // проверить корректность сертификата
        if (provider == null || provider.length() == 0) verify(publicKey);
        else {
            // получить данные для проверки 
            byte[] data = getTBSCertificate(); byte[] signature = getSignature();
        
            // указать алгоритм подписи
            Signature algorithm = Signature.getInstance(getSigAlgName());

            // инициализировать алгоритм и обработать данные
            algorithm.initVerify(publicKey); algorithm.update(data, 0, data.length);
            
            // проверить подпись
            if (!algorithm.verify(signature)) throw new SignatureException();
        }
    }
}
