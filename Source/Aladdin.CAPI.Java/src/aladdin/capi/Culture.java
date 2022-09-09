package aladdin.capi;
import aladdin.capi.pbe.*; 
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.*; 
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Национальные особенности
///////////////////////////////////////////////////////////////////////////
public abstract class Culture
{
    // параметры алгоритмов
	public AlgorithmIdentifier hashAlgorithm              (IRand rand) throws IOException { return null; } 
    public AlgorithmIdentifier hmacAlgorithm              (IRand rand) throws IOException { return null; } 
	public AlgorithmIdentifier cipherAlgorithm            (IRand rand) throws IOException { return null; } 
	public AlgorithmIdentifier keyWrapAlgorithm           (IRand rand) throws IOException { return null; } 
	public AlgorithmIdentifier ciphermentAlgorithm        (IRand rand) throws IOException { return null; } 
    public AlgorithmIdentifier signHashAlgorithm          (IRand rand) throws IOException { return null; } 
    public AlgorithmIdentifier signDataAlgorithm          (IRand rand) throws IOException { return null; } 
	public AlgorithmIdentifier transportKeyAlgorithm      (IRand rand) throws IOException { return null; }
	public AlgorithmIdentifier transportAgreementAlgorithm(IRand rand) throws IOException { return null; } 
    
    // параметры шифрования по паролю
    public PBECulture pbe(PBEParameters parameters)
    {
        // параметры шифрования по паролю
        return new PBEDefaultCulture(this, parameters, true); 
    }
	///////////////////////////////////////////////////////////////////////
	// Параметры шифрования на открытом ключе (KeyX)
	///////////////////////////////////////////////////////////////////////
    public AlgorithmIdentifier keyxParameters(
        Factory factory, SecurityStore scope, IRand rand, KeyUsage keyUsage) throws IOException
    {
        // при допустимости транспорта ключа
        if (keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
        {
            // создать список параметров 
            AlgorithmIdentifier keyxParameters; 
            
            // получить параметры алгоритма обмена
            if ((keyxParameters = transportKeyAlgorithm(rand)) != null)
            try {
                // получить алгоритм транспорта ключа
                IAlgorithm algorithm = factory.createAlgorithm(
                    scope, keyxParameters, TransportKeyWrap.class
                );
                // проверить наличие алгоритма транспорта ключа
                if (algorithm != null) { RefObject.release(algorithm); return keyxParameters; }
            }
            // обработать возможную ошибку
            catch (IOException e) {}
        }
        // при допустимости согласования ключа ключа
        if (keyUsage.containsAny(KeyUsage.KEY_AGREEMENT))
        {
            // создать список параметров 
            AlgorithmIdentifier keyxParameters; 
            
            // получить параметры алгоритма обмена
            if ((keyxParameters = transportAgreementAlgorithm(rand)) != null)
            try {
                // получить алгоритм согласования ключа
                IAlgorithm algorithm = factory.createAlgorithm(
                    scope, keyxParameters, ITransportAgreement.class
                );
                // проверить наличие алгоритма транспорта ключа
                if (algorithm != null) { RefObject.release(algorithm); return keyxParameters; }
            }
            // обработать возможную ошибку
            catch (IOException e) {}
        }
        return null; 
    }
	///////////////////////////////////////////////////////////////////////
	// Зашифровать данные на открытом ключе (KeyX)
	///////////////////////////////////////////////////////////////////////
    public static ContentInfo keyxEncryptData(Culture culture, 
        Factory factory, SecurityStore scope, IRand rand, 
        Certificate recipientCertificate, CMSData data, 
        Attributes attributes) throws IOException
	{
        // зашифровать данные
        return Culture.keyxEncryptData(culture, factory, scope, rand, 
            recipientCertificate, recipientCertificate.keyUsage(), data, attributes
        ); 
    }
    public static ContentInfo keyxEncryptData(Culture culture, 
        Factory factory, SecurityStore scope, IRand rand, 
        Certificate recipientCertificate, KeyUsage recipientUsage, 
        CMSData data, Attributes attributes) throws IOException
	{
        // зашифровать данные
        return Culture.keyxEncryptData(culture, factory, scope,
            rand, new Certificate[] { recipientCertificate }, 
            new KeyUsage[] { recipientUsage }, 
            new Culture[] { culture }, data, attributes
        ); 
    }
	public static ContentInfo keyxEncryptData(
        Culture culture, Factory factory, SecurityStore scope, 
        IRand rand, Certificate[] recipientCertificates, 
        Culture[] cultures, CMSData data, Attributes attributes) throws IOException
    {
        // создать список использований ключа
        KeyUsage[] recipientUsages = new KeyUsage[recipientCertificates.length]; 

        // заполнить список использования ключа
        for (int i = 0; i < recipientCertificates.length; i++)
        {
            // указать использование ключа
            recipientUsages[i] = recipientCertificates[i].keyUsage(); 
        }
        // зашифровать данные
        return keyxEncryptData(culture, factory, scope, rand, 
            recipientCertificates, recipientUsages, cultures, data, attributes
        ); 
    }
	public static ContentInfo keyxEncryptData(
        Culture culture, Factory factory, SecurityStore scope, IRand rand, 
        Certificate[] recipientCertificates, KeyUsage[] recipientUsages, 
        Culture[] cultures, CMSData data, Attributes attributes) throws IOException
	{
        // проверить указание алгоритмов
        if (culture == null) throw new UnsupportedOperationException(); 
        
        // указать идентификатор типа 
        ObjectIdentifier dataType = new ObjectIdentifier(
            aladdin.asn1.iso.pkcs.pkcs7.OID.ENVELOPED_DATA
        ); 
        // создать список параметров 
        AlgorithmIdentifier[] keyxParameters = 
            new AlgorithmIdentifier[recipientCertificates.length]; 
        
        // указать алгоритм шифрования
        AlgorithmIdentifier cipherParameters = culture.cipherAlgorithm(rand); 
            
        // проверить указание алгоритма
        if (cipherParameters == null) throw new UnsupportedOperationException(); 

        // для всех сертификатов
        for (int i = 0; i < keyxParameters.length; i++)
        {
            // указать используемую культуру
            Culture keyxCulture = (cultures != null) ? cultures[i] : culture; 
            
            // получить параметры алгоритма
            keyxParameters[i] = keyxCulture.keyxParameters(factory, scope, rand, recipientUsages[i]); 
            
            // проверить отсутствие ошибок
            if (keyxParameters[i] == null) throw new UnsupportedOperationException(); 
        }
        // зашифровать данные
        EnvelopedData envelopedData = CMS.keyxEncryptData(
            factory, scope, rand, recipientCertificates, recipientUsages, 
            keyxParameters, cipherParameters, data, attributes
        ); 
        // вернуть закодированную структуру
        return new ContentInfo(dataType, envelopedData); 
    }
	public static ContentInfo keyxEncryptData(
        Culture culture, IRand rand, IPrivateKey privateKey, 
        Certificate[] certificateChain, Certificate recipientCertificate, 
        CMSData data, Attributes attributes) throws IOException
    {
        // зашифровать данные
        return keyxEncryptData(culture, rand, privateKey, certificateChain, 
            recipientCertificate, recipientCertificate.keyUsage(), data, attributes
        ); 
    }
	public static ContentInfo keyxEncryptData(
        Culture culture, IRand rand, IPrivateKey privateKey, 
        Certificate[] certificateChain, Certificate recipientCertificate, 
        KeyUsage recipientUsage, CMSData data, Attributes attributes) throws IOException
    {
        // зашифровать данные
        return keyxEncryptData(culture, rand, privateKey, certificateChain, 
            new Certificate[] { recipientCertificate }, new KeyUsage[] { recipientUsage }, 
            new Culture[] { culture }, data, attributes
        ); 
    }
	public static ContentInfo keyxEncryptData(Culture culture, IRand rand, 
        IPrivateKey privateKey, Certificate[] certificateChain, 
        Certificate[] recipientCertificates, Culture[] cultures, 
        CMSData data, Attributes attributes) throws IOException
    {
        // создать список использований ключа
        KeyUsage[] recipientUsages = new KeyUsage[recipientCertificates.length]; 

        // заполнить список использования ключа
        for (int i = 0; i < recipientCertificates.length; i++)
        {
            // указать использование ключа
            recipientUsages[i] = recipientCertificates[i].keyUsage(); 
        }
        // зашифровать данные
        return keyxEncryptData(culture, rand, privateKey, certificateChain, 
            recipientCertificates, recipientUsages, cultures, data, attributes
        ); 
    }
	public static ContentInfo keyxEncryptData(Culture culture, IRand rand, 
        IPrivateKey privateKey, Certificate[] certificateChain, 
        Certificate[] recipientCertificates, KeyUsage[] recipientUsages, 
        Culture[] cultures, CMSData data, Attributes attributes) throws IOException
	{
        // указать идентификатор типа 
        ObjectIdentifier dataType = new ObjectIdentifier(
            aladdin.asn1.iso.pkcs.pkcs7.OID.ENVELOPED_DATA
        ); 
        // создать список параметров 
        AlgorithmIdentifier[] keyxParameters = 
            new AlgorithmIdentifier[recipientCertificates.length]; 

        // получить параметры алгоритма шифрования
        AlgorithmIdentifier cipherParameters = culture.cipherAlgorithm(rand);
            
        // проверить указание алгоритма
        if (cipherParameters == null) throw new UnsupportedOperationException(); 
            
        // для всех сертификатов
        for (int i = 0; i < keyxParameters.length; i++)
        {
            // указать используемую культуру
            Culture keyxCulture = (cultures != null) ? cultures[i] : culture; 
                
            // получить параметры алгоритма
            keyxParameters[i] = keyxCulture.keyxParameters( 
                privateKey.factory(), privateKey.scope(), rand, recipientUsages[i]
            ); 
            // проверить отсутствие ошибок
            if (keyxParameters[i] == null) throw new UnsupportedOperationException(); 
        }
        // зашифровать данные
        EnvelopedData envelopedData = CMS.keyxEncryptData( 
            rand, privateKey, certificateChain, recipientCertificates, 
            recipientUsages, keyxParameters, cipherParameters, data, attributes
        ); 
        // вернуть закодированную структуру
        return new ContentInfo(dataType, envelopedData); 
    }
	///////////////////////////////////////////////////////////////////////
	// Подписать данные на личном ключе
    // Национальные особенности выбираются согласно сертификату
	///////////////////////////////////////////////////////////////////////
	public static ContentInfo signData(Culture culture, IRand rand, 
        IPrivateKey privateKey, Certificate[] certificateChain, CMSData data, 
        Attributes[] authAttributes, Attributes[] unauthAttributes) throws IOException
    {
        // подписать данные
        return Culture.signData(new Culture[] { culture }, rand, 
            new IPrivateKey[] { privateKey }, new Certificate[][] { certificateChain }, 
            data, authAttributes, unauthAttributes
        ); 
    }
	public static ContentInfo signData(Culture[] cultures, IRand rand, 
        IPrivateKey[] privateKeys, Certificate[][] certificatesChains, CMSData data, 
        Attributes[] authAttributes, Attributes[] unauthAttributes) throws IOException
	{
        // указать идентификатор типа 
        ObjectIdentifier dataType = new ObjectIdentifier(
            aladdin.asn1.iso.pkcs.pkcs7.OID.SIGNED_DATA
        ); 
	    // создать список параметров хэширования
	    AlgorithmIdentifier[] hashParameters = 
            new AlgorithmIdentifier[privateKeys.length];

        // создать список параметров подписи
	    AlgorithmIdentifier[] signHashParameters = 
            new AlgorithmIdentifier[privateKeys.length];

        // для всех личных ключей
        for (int i = 0; i < privateKeys.length; i++)
        { 
            // получить параметры алгоритма хэширования
            hashParameters[i] = cultures[i].hashAlgorithm(rand);
                
            // получить параметры алгоритма подписи
            signHashParameters[i] = cultures[i].signHashAlgorithm(rand); 
                
            // проверить наличие параметров
            if (hashParameters[i] == null || signHashParameters[i] == null)
            {
                // при ошибке выбросить исключение
                throw new UnsupportedOperationException(); 
            }
        }
        // подписать данные
        SignedData signedData = CMS.signData(rand, 
            privateKeys, certificatesChains, hashParameters, 
            signHashParameters, data, authAttributes, unauthAttributes
        ); 
        // вернуть закодированную структуру
        return new ContentInfo(dataType, signedData); 
	}
}
