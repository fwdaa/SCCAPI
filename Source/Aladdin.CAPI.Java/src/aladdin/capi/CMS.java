package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.*; 
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.iso.pkcs.pkcs9.*; 
import java.security.*; 
import java.io.*; 
import java.util.*; 
import java.util.Collection; 

public final class CMS
{
	///////////////////////////////////////////////////////////////////////
	// Захэшировать данные
	///////////////////////////////////////////////////////////////////////
	public static DigestedData hashData(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, CMSData data) throws IOException
    {
		// установить версию структуры
		Integer version = new Integer(
            data.type.equals(aladdin.asn1.iso.pkcs.pkcs7.OID.DATA) ? 0 : 2
        ); 
		// закодировать хэшируемые данные
		EncapsulatedContentInfo encapContentInfo = new EncapsulatedContentInfo(
            new ObjectIdentifier(data.type), new OctetString(data.content)
        ); 
		// создать алгоритм хэширования данных
		try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // при ошибке выбросить исключение
            if (hashAlgorithm == null) throw new UnsupportedOperationException();
            
            // вычислить хэш-значение
            byte[] hash = hashAlgorithm.hashData(data.content, 0, data.content.length); 
            
            // вернуть структуру 
            return new DigestedData(version, parameters, encapContentInfo, new OctetString(hash)); 
        }
    }
	public static CMSData verifyHash(Factory factory, SecurityStore scope, 
        DigestedData digestedData) throws IOException
    {
		// извлечь содержимое
		EncapsulatedContentInfo encapContentInfo = digestedData.encapContentInfo(); 
        
        // проверить наличие содержимого
        if (encapContentInfo.eContent() == null) throw new IllegalStateException(); 
        
        // извлечь данные для хэширования и хэш-значение
        byte[] data = encapContentInfo.eContent().value(); byte[] check = digestedData.digest().value(); 
        
		// создать алгоритм хэширования данных
		try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
            scope, digestedData.digestAlgorithm(), Hash.class))
        {
            // при ошибке выбросить исключение
            if (hashAlgorithm == null) throw new UnsupportedOperationException();
            
            // вычислить хэш-значение
            byte[] hash = hashAlgorithm.hashData(data, 0, data.length); 
            
            // сравнить хэш-значение
            if (!Arrays.equals(hash, check)) throw new IOException(); 
            
            // вернуть исходные данные
            return new CMSData(encapContentInfo.eContentType().value(), data); 
        }
    }
	///////////////////////////////////////////////////////////////////////
	// Зашифровать личный ключ на симметричном ключе
	///////////////////////////////////////////////////////////////////////
	public static EncryptedPrivateKeyInfo encryptPrivateKey(
		Factory factory, SecurityStore scope, ISecretKey key, 
        AlgorithmIdentifier parameters, PrivateKeyInfo privateKeyInfo) 
        throws IOException, InvalidKeyException
	{
		// создать алгоритм шифрования данных
		try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // при ошибке выбросить исключение
            if (cipher == null) throw new UnsupportedOperationException();
            
            // извлечь зашифрованные данные
            byte[] decrypted = privateKeyInfo.encoded(); 

            // зашифровать данные
            byte[] encrypted = cipher.encrypt(
                key, PaddingMode.PKCS5, decrypted, 0, decrypted.length
            );
            // закодировать зашифрованные данные
            return new EncryptedPrivateKeyInfo(parameters, new OctetString(encrypted));
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Расшифровать личный ключ на симметричном ключе
	///////////////////////////////////////////////////////////////////////
	public static PrivateKeyInfo decryptPrivateKey(
        Factory factory, SecurityStore scope, ISecretKey key, 
        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo) 
        throws IOException, InvalidKeyException
	{
		// получить параметры алгоритма шифрования
		AlgorithmIdentifier parameters = encryptedPrivateKeyInfo.encryptionAlgorithm(); 

		// получить зашифрованные данные
		byte[] encrypted = encryptedPrivateKeyInfo.encryptedData().value();
        
		// создать алгоритм шифрования
		try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // при ошибке выбросить исключение
            if (cipher == null) throw new UnsupportedOperationException();
            
            // расшифровать данные
            byte[] data = cipher.decrypt(key, PaddingMode.PKCS5, encrypted, 0, encrypted.length);
            
            // вернуть закодированный ключ
            return new PrivateKeyInfo(Encodable.decode(data));
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Зашифровать личный ключ на ассиметричном ключе
	///////////////////////////////////////////////////////////////////////
	public static EncryptedPrivateKeyInfo encryptPrivateKey(
        Factory factory, SecurityStore scope, IRand rand, Certificate certificate, 
        AlgorithmIdentifier parameters, PrivateKeyInfo privateKeyInfo) throws IOException
	{
        // извлечь открытый ключ
        IPublicKey publicKey = certificate.getPublicKey(factory); 
        
		// создать алгоритм зашифрования
		try (Encipherment encryption = (Encipherment)factory.createAlgorithm(
            scope, parameters, Encipherment.class))
        {
            // при ошибке выбросить исключение
            if (encryption == null) throw new UnsupportedOperationException();
            
            // зашифровать личный ключ
            byte[] encrypted = encryption.encrypt(
                publicKey, rand, privateKeyInfo.encoded()
            ); 
            // вернуть зашифрованный личный ключ
            return new EncryptedPrivateKeyInfo(parameters, new OctetString(encrypted));
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Расшифровать личный ключ на ассиметричном ключе
	///////////////////////////////////////////////////////////////////////
	public static PrivateKeyInfo decryptPrivateKey(IPrivateKey privateKey, 
        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo) throws IOException
	{
		// извлечь параметры шифрования
		AlgorithmIdentifier parameters = encryptedPrivateKeyInfo.encryptionAlgorithm(); 

		// создать алгоритм расшифрования
		try (Decipherment decryption = (Decipherment)privateKey.factory().
            createAlgorithm(privateKey.scope(), parameters, Decipherment.class))
        {
            // при ошибке выбросить исключение
            if (decryption == null) throw new UnsupportedOperationException();
            
            // расшифровать личный ключ
            byte[] decrypted = decryption.decrypt(privateKey, 
                encryptedPrivateKeyInfo.encryptedData().value()
            ); 
            // вернуть расшифрованный личный ключ
            return new PrivateKeyInfo(Encodable.decode(decrypted));
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Зашифровать данные на симметричном ключе
	///////////////////////////////////////////////////////////////////////
	public static EncryptedData encryptData(Factory factory, SecurityStore scope, 
        ISecretKey key, AlgorithmIdentifier parameters, CMSData data, 
        Attributes unprotectedAttributes) throws IOException, InvalidKeyException
	{
		// создать алгоритм шифрования данных
		try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // при ошибке выбросить исключение
            if (cipher == null) throw new UnsupportedOperationException(); byte[] encrypted = null; 
            
            // создать преобразование зашифрования
            try (Transform encryption = cipher.createEncryption(key, PaddingMode.PKCS5))
            {
                // при наличии контроля целостности
                if (encryption instanceof TransformCheck)
                {
                    // выделить память для атрибутов
                    List<Attribute> listAttributes = new ArrayList<Attribute>(); 
                    
                    // при наличии атрибутов
                    if (unprotectedAttributes != null) 
                    {
                        // добавить атрибуты в список
                        for (Attribute attribute : unprotectedAttributes) listAttributes.add(attribute);
                    }
                    // выполнить преобразование типа
                    TransformCheck encryptionCheck = (TransformCheck)encryption; 
                    
                    // зашифровать данные
                    encrypted = encryptionCheck.transformData(
                        data.content, 0, data.content.length, listAttributes
                    ); 
                }
                // зашифровать данные
                else encrypted = encryption.transformData(data.content, 0, data.content.length); 
            }
            // установить версию структуры
            Integer version = new Integer(unprotectedAttributes == null ? 0 : 2); 
        
            // закодировать зашифрованные данные
            EncryptedContentInfo encryptedContentInfo = new EncryptedContentInfo(
                new ObjectIdentifier(data.type), parameters, new OctetString(encrypted)
            );
            // вернуть структруру
            return new EncryptedData(version, encryptedContentInfo, unprotectedAttributes); 
        }
    }
	///////////////////////////////////////////////////////////////////////
	// Расшифровать данные на симметричном ключе
	///////////////////////////////////////////////////////////////////////
	public static CMSData decryptData(Factory factory, SecurityStore scope, 
        ISecretKey key, EncryptedContentInfo encryptedContentInfo, 
        Attributes unprotectedAttributes) throws IOException, InvalidKeyException
	{
		// получить параметры алгоритма шифрования
		AlgorithmIdentifier cipherParameters = encryptedContentInfo.contentEncryptionAlgorithm(); 

		// получить зашифрованные данные
		byte[] encrypted = encryptedContentInfo.encryptedContent().value();

		// создать алгоритм шифрования
		try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
        {
            // при ошибке выбросить исключение
            if (cipher == null) throw new UnsupportedOperationException(); byte[] data = null; 
            
            // получить преобразование расшифрования
            try (Transform decryption = cipher.createDecryption(key, PaddingMode.PKCS5))
            {
                // при наличии контроля целостности
                if (decryption instanceof TransformCheck)
                {
                    // выделить память для атрибутов
                    List<Attribute> listAttributes = new ArrayList<Attribute>(); 
                    
                    // при наличии атрибутов
                    if (unprotectedAttributes != null) 
                    {
                        // добавить атрибуты в список
                        for (Attribute attribute : unprotectedAttributes) listAttributes.add(attribute);
                    }
                    // выполнить преобразование типа
                    TransformCheck decryptionCheck = (TransformCheck)decryption; 
                    
                    // расшифровать данные
                    data = decryptionCheck.transformData(encrypted, 0, encrypted.length, listAttributes); 
                }
                // расшифровать данные
                else data = decryption.transformData(encrypted, 0, encrypted.length); 
            }
            // вернуть извлеченные данные
            return new CMSData(encryptedContentInfo.contentType().value(), data);
        }
	}
	public static CMSData decryptData(Factory factory, SecurityStore scope, 
        ISecretKey key, EncryptedData encryptedData) throws IOException, InvalidKeyException
	{
        // расшифровать данные
        return decryptData(factory, scope, key, 
            encryptedData.encryptedContentInfo(), encryptedData.unprotectedAttrs()
        ); 
	}
	public static CMSData decryptData(Factory factory, SecurityStore scope, 
        ISecretKey key, byte[] keyID, EnvelopedData envelopedData) 
        throws IOException, InvalidKeyException
	{
        // получить информацию о зашифрованном ключе
		KEKRecipientInfo recipientInfo = new KEKRecipientInfo(
            envelopedData.recipientInfos().get(new OctetString(keyID))
        ); 
		// получить параметры алгоритма шифрования
		AlgorithmIdentifier cipherParametersKEK = recipientInfo.keyEncryptionAlgorithm(); 

        // извлечь зашифрованный ключ
        byte[] encryptedKey = recipientInfo.encryptedKey().content(); 

        // создать алгоритм шифрования данных
		try (Cipher cipherKEK = (Cipher)factory.createAlgorithm(scope, cipherParametersKEK, Cipher.class))
        { 
            // проверить наличие алгоритма
            if (cipherKEK == null) throw new UnsupportedOperationException();
            
            // расшифровать ключ шифрования данных
            byte[] valueCEK = cipherKEK.decrypt(key, PaddingMode.PKCS5, encryptedKey, 0, encryptedKey.length); 

            // получить параметры алгоритма шифрования
            AlgorithmIdentifier cipherParametersCEK = 
                envelopedData.encryptedContentInfo().contentEncryptionAlgorithm(); 
            
            // создать алгоритм шифрования
            try (Cipher cipherCEK = (Cipher)factory.createAlgorithm(scope, cipherParametersCEK, Cipher.class))
            {
                // при ошибке выбросить исключение
                if (cipherCEK == null) throw new UnsupportedOperationException();
            
                // указать используемый ключ
                try (ISecretKey CEK = cipherCEK.keyFactory().create(valueCEK))
                {
                    // расшифровать данные
                    return CMS.decryptData(factory, scope, CEK, 
                        envelopedData.encryptedContentInfo(), envelopedData.unprotectedAttrs()
                    ); 
                }
            }
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Зашифровать ключ на пароле
	///////////////////////////////////////////////////////////////////////
	public static PasswordRecipientInfo passwordEncryptKey(
        Factory factory, SecurityStore scope, IRand rand, 
        ISecretKey password, AlgorithmIdentifier keyDeriveParameters,  
		AlgorithmIdentifier keyWrapParameters, ISecretKey CEK) 
        throws IOException, InvalidKeyException
	{
		// создать алгоритм наследования ключа
		try (KeyDerive keyDerive = (KeyDerive)factory.createAlgorithm(
            scope, keyDeriveParameters, KeyDerive.class))
        {
            // при ошибке выбросить исключение
            if (keyDerive == null) throw new UnsupportedOperationException();
            
            // создать алгоритм шифрования ключа
            try (KeyWrap keyWrap = (KeyWrap)factory.createAlgorithm(
                scope, keyWrapParameters, KeyWrap.class))
            {
                // при ошибке выбросить исключение
                if (keyWrap == null) throw new UnsupportedOperationException();
                
                // определить допустимые размеры ключей
                int[] keySizes = keyWrap.keyFactory().keySizes(); int keySize = -1; 
        
                // указать рекомендуемый размер ключа
                if (keySizes != null && keySizes.length == 1) keySize = keySizes[0]; 
        
                // создать ключ шифрования ключа
                try (ISecretKey KEK = keyDerive.deriveKey(password, null, keyWrap.keyFactory(), keySize)) 
                {
                    // проверить допустимость размера ключа
                    if (!KeySizes.contains(keySizes, KEK.length())) 
                    {
                        // выбросить исключение
                        throw new IllegalStateException();
                    }
                    // зашифровать ключ
                    byte[] encryptedKey = keyWrap.wrap(rand, KEK, CEK);

                    // закодировать зашифрованный ключ с параметрами
                    return new PasswordRecipientInfo(
                        new Integer(0), keyDeriveParameters, 
                        keyWrapParameters, new OctetString(encryptedKey)
                    );
                }
            }
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Расшифровать ключ на пароле
	///////////////////////////////////////////////////////////////////////
	public static ISecretKey passwordDecryptKey(Factory factory, SecurityStore scope, 
        ISecretKey password, PasswordRecipientInfo recipientInfo, SecretKeyFactory keyFactory) 
        throws IOException, InvalidKeyException
	{
		// получить информацию об алгоритме наследования ключа
		AlgorithmIdentifier keyDeriveParameters = recipientInfo.keyDerivationAlgorithm();

		// получить информацию об алгоритме шифрования ключа
		AlgorithmIdentifier keyWrapParameters = recipientInfo.keyEncryptionAlgorithm();
			
		// создать алгоритм наследования ключа
		try (KeyDerive keyDerive = (KeyDerive)factory.createAlgorithm(
            scope, keyDeriveParameters, KeyDerive.class))
        {
            // при ошибке выбросить исключение
            if (keyDerive == null) throw new UnsupportedOperationException();
            
            // создать алгоритм шифрования ключа
            try (KeyWrap keyWrap = (KeyWrap)factory.createAlgorithm(
                scope, keyWrapParameters, KeyWrap.class)) 
            {
                // при ошибке выбросить исключение
                if (keyWrap == null) throw new UnsupportedOperationException();
                
                // определить допустимые размеры ключей
                int[] keySizes = keyWrap.keyFactory().keySizes(); int keySize = -1; 
        
                // указать рекомендуемый размер ключа
                if (keySizes != null && keySizes.length == 1) keySize = keySizes[0]; 
        
                // создать ключ шифрования ключа
                try (ISecretKey KEK = keyDerive.deriveKey(password, null, keyWrap.keyFactory(), keySize)) 
                { 
                    // проверить допустимость размера ключа
                    if (!KeySizes.contains(keySizes, KEK.length())) 
                    {
                        // выбросить исключение
                        throw new IllegalStateException();
                    }
                    // расшифровать ключ
                    return keyWrap.unwrap(KEK, recipientInfo.encryptedKey().value(), keyFactory); 
                }
            }
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Зашифровать данные по паролю
	///////////////////////////////////////////////////////////////////////
	public static EnvelopedData passwordEncryptData(
        Factory factory, SecurityStore scope, IRand rand, 
        ISecretKey[] passwords, AlgorithmIdentifier cipherParameters, 
        AlgorithmIdentifier[] keyDeriveParameters, AlgorithmIdentifier[] keyWrapParameters, 
        CMSData data, Attributes unprotectedAttributes) throws IOException, InvalidKeyException
	{
		// создать алгоритм шифрования данных
		try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
        {
            // проверить наличие алгоритма
            if (cipher == null) throw new UnsupportedOperationException();
            
            // определить допустимые размеры ключей
            int[] keySizes = cipher.keyFactory().keySizes(); 
            
            // проверить наличие фиксированного размера ключа
            if (keySizes == null || keySizes.length != 1) 
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException();
            }
            // преобразовать тип ключа
            try (ISecretKey CEK = cipher.keyFactory().generate(rand, keySizes[0]))
            {
                // зашифровать данные на ключе
                EncryptedData encryptedData = CMS.encryptData(
                    factory, scope, CEK, cipherParameters, data, unprotectedAttributes
                ); 
                // создать список для зашифрованных ключей
                List<IEncodable> listRecipientInfos = new ArrayList<IEncodable>(); 

                // для каждого получателя
                for (int i = 0; i < passwords.length; i++)
                {
                    // зашифровать ключ по паролю
                    PasswordRecipientInfo recipientInfo = CMS.passwordEncryptKey(
                        factory, scope, rand, passwords[i], 
                        keyDeriveParameters[i], keyWrapParameters[i], CEK
                    ); 
                    // поместить зашифрованный ключ в список
                    listRecipientInfos.add(Encodable.encode(
                        Tag.context(3), recipientInfo.pc(), recipientInfo.content()
                    )); 
                }
                // закодировать список зашифрованных ключей
                RecipientInfos recipientInfos = new RecipientInfos(
                    listRecipientInfos.toArray(new IEncodable[0])
                );
                // закодировать структуру CMS
                return new EnvelopedData(new Integer(0), null, 
                    recipientInfos, encryptedData.encryptedContentInfo(), 
                    encryptedData.unprotectedAttrs()
                );
            }
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Расшифровать данные по паролю
	///////////////////////////////////////////////////////////////////////
	public static CMSData passwordDecryptData(Factory factory, 
        SecurityStore scope, ISecretKey password, int index, EnvelopedData envelopedData) 
        throws IOException, InvalidKeyException
	{
		// извлечь зашифрованные данные
		EncryptedContentInfo encryptedContentInfo = envelopedData.encryptedContentInfo(); 

		// получить информацию о зашифрованном ключе
		PasswordRecipientInfo recipientInfo = 
			new PasswordRecipientInfo(envelopedData.recipientInfos().get(index)); 
        
		// получить параметры алгоритма шифрования
		AlgorithmIdentifier cipherParameters = encryptedContentInfo.contentEncryptionAlgorithm(); 
        
		// создать алгоритм шифрования
		try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
        {
            // при ошибке выбросить исключение
            if (cipher == null) throw new UnsupportedOperationException();
            
            // расшифровать ключ шифрования данных по паролю
            try (ISecretKey CEK = CMS.passwordDecryptKey(
                factory, scope, password, recipientInfo, cipher.keyFactory())) 
            {
                // расшифровать данные
                return CMS.decryptData(factory, scope, CEK, 
                    encryptedContentInfo, envelopedData.unprotectedAttrs()
                ); 
            }
        }
	}
	public static CMSData passwordDecryptData(Factory factory, SecurityStore scope, 
        ISecretKey password, ContentInfo contentInfo) throws IOException, InvalidKeyException
	{
        // в зависимости от идентификатора
        if (contentInfo.contentType().value().equals(aladdin.asn1.iso.pkcs.pkcs7.OID.ENCRYPTED_DATA))
        {
            // раскодировать зашифрованные данные
            EncryptedData encryptedData = new EncryptedData(contentInfo.inner()); 

            // расшифровать данные
            return decryptData(factory, scope, password, encryptedData); 
        }
        // в зависимости от идентификатора
        if (contentInfo.contentType().value().equals(aladdin.asn1.iso.pkcs.pkcs7.OID.ENVELOPED_DATA))
        {
            // раскодировать зашифрованные данные
            EnvelopedData envelopedData = new EnvelopedData(contentInfo.inner()); 

            // расшифровать данные
            return passwordDecryptData(factory, scope, password, 0, envelopedData); 
        }
        // при ошибке выбросить исключение
        throw new UnsupportedOperationException(); 
    }
	///////////////////////////////////////////////////////////////////////
	// Зашифровать ключ через алгоритм обмена
	///////////////////////////////////////////////////////////////////////
	public static KeyTransRecipientInfo transportEncryptKey(
        Factory factory, SecurityStore scope, IRand rand, 
        Certificate certificate, Tag recipientChoice, 
        AlgorithmIdentifier parameters, ISecretKey key) 
        throws IOException, InvalidKeyException
	{
        // указать номер версии структуры
        Integer version = new Integer(0); IEncodable rid = null; 

        // указать способ идентификации получателя
        if (recipientChoice.equals(Tag.ANY)) recipientChoice = Tag.SEQUENCE; 
        
        // указать способ идентификации получателя
        if (recipientChoice.equals(Tag.SEQUENCE)) rid = certificate.issuerSerialNumber(); 

        // в зависимости от способа идентификации
        else if (recipientChoice.equals(Tag.context(0))) { version = new Integer(2);
            
            // получить идентификатор ключа
            OctetString subjectKeyIdentifier = certificate.subjectKeyIdentifier(); 

            // проверить наличие идентификатора
            if (subjectKeyIdentifier == null) throw new UnsupportedOperationException(); 

            // закодировать идентификатор ключа
            rid = Encodable.encode(recipientChoice, 
                subjectKeyIdentifier.pc(), subjectKeyIdentifier.content()
            ); 
        }
        // извлечь открытый ключ
        IPublicKey publicKey = certificate.getPublicKey(factory); 
        
		// создать алгоритм обмена ключа
		try (TransportKeyWrap keyTransport = (TransportKeyWrap)
            factory.createAlgorithm(scope, parameters, TransportKeyWrap.class))
        {
            // при ошибке выбросить исключение
            if (keyTransport == null) throw new UnsupportedOperationException();
            
            // зашифровать ключ шифрования данных
            TransportKeyData transportData = keyTransport.wrap(
                parameters, publicKey, rand, key
            );
            // закодировать зашифрованный ключ с параметрами
            return new KeyTransRecipientInfo(
                version, rid, transportData.algorithm, 
                new OctetString(transportData.encryptedKey)
            );
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Расшифровать ключ через алгоритм обмена
	///////////////////////////////////////////////////////////////////////
	public static ISecretKey transportDecryptKey(IPrivateKey privateKey, 
		KeyTransRecipientInfo recipientInfo, SecretKeyFactory keyFactory) throws IOException
	{
		// получить информацию об используемом алгоритме
		AlgorithmIdentifier parameters = recipientInfo.keyEncryptionAlgorithm();

		// получить значение зашифрованного ключа
		OctetString encryptedKey = recipientInfo.encryptedKey();

        // создать алгоритм обмена
		try (TransportKeyUnwrap keyTransport = (TransportKeyUnwrap)
            privateKey.factory().createAlgorithm(privateKey.scope(), parameters, TransportKeyUnwrap.class))
        {
            // при ошибке выбросить исключение
            if (keyTransport == null) throw new UnsupportedOperationException();
            
            // сформировать данные
            TransportKeyData data = new TransportKeyData(parameters, encryptedKey.value()); 

            // вычислить ключ шифрования данных
            return keyTransport.unwrap(privateKey, data, keyFactory);
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Зашифровать ключ через алгоритм согласования
	///////////////////////////////////////////////////////////////////////
	public static KeyAgreeRecipientInfo agreementEncryptKey(IRand rand, 
		IPrivateKey privateKey, IPublicKey publicKey, AlgorithmIdentifier parameters, 
        Certificate[] recipientCertificates, ISecretKey key) 
        throws IOException, InvalidKeyException
	{
        // создать список открытых ключей
        IPublicKey[] recipientPublicKeys = new IPublicKey[recipientCertificates.length]; 
        
        // для всех получателей
        for (int i = 0; i < recipientCertificates.length; i++)
        {
            // получить способ использования ключа
            KeyUsage keyUsage = recipientCertificates[i].keyUsage(); 

            // проверить допустимость использования ключа
            if (keyUsage.containsAny(KeyUsage.DECIPHER_ONLY))
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException(); 
            }
            // сохранить открытый ключ
            recipientPublicKeys[i] = recipientCertificates[i].getPublicKey(privateKey.factory()); 
        }
        // выделить память для зашифрованных ключей
		RecipientEncryptedKey[] recipientEncryptedKeys = 
			new RecipientEncryptedKey[recipientCertificates.length]; 

		// создать алгоритм согласования ключа
		try (ITransportAgreement keyAgreement = (ITransportAgreement)
            privateKey.factory().createAlgorithm(
                privateKey.scope(), parameters, ITransportAgreement.class)) 
        {
            // при ошибке выбросить исключение
            if (keyAgreement == null) throw new UnsupportedOperationException();
            
            // зашифровать ключ для получателей
            TransportAgreementData data = keyAgreement.wrap(
                privateKey, publicKey, recipientPublicKeys, rand, key
            ); 
            // закодировать случайные данные
            OctetString ukm = (data.random != null) ? new OctetString(data.random) : null; 

            // для всех получателей
            for (int i = 0; i < recipientCertificates.length; i++)
            {
                // закодировать зашифрованный ключ
                recipientEncryptedKeys[i] = new RecipientEncryptedKey(
                    recipientCertificates[i].issuerSerialNumber(), 
                        new OctetString(data.encryptedKeys[i])
                ); 
            }
            // закодировать открытый ключ
            SubjectPublicKeyInfo publicKeyInfo = data.publicKey.encoded(); 
                
            // указать способ идентификации отправителя
            IEncodable originator = Encodable.encode(
                Tag.context(1), publicKeyInfo.pc(), publicKeyInfo.content()
            ); 
            // закодировать зашифрованный ключ с параметрами
            return new KeyAgreeRecipientInfo(
                new Integer(3), originator, ukm, parameters, 
                new RecipientEncryptedKeys(recipientEncryptedKeys)
            );
        }
	}
	public static KeyAgreeRecipientInfo agreementEncryptKey(
		IRand rand, IPrivateKey privateKey, Certificate certificate, 
        Tag senderChoice, AlgorithmIdentifier parameters, 
        Certificate[] recipientCertificates, ISecretKey key) 
        throws IOException, InvalidKeyException
	{
        // указать используемый провайдер
        Factory factory = privateKey.factory(); IEncodable originator;
        
        // извлечь открытый ключ
        IPublicKey senderPublicKey = certificate.getPublicKey(factory); 
        
        // создать список открытых ключей
        IPublicKey[] recipientPublicKeys = new IPublicKey[recipientCertificates.length]; 
        
        // для всех получателей
        for (int i = 0; i < recipientCertificates.length; i++)
        {
            // получить способ использования ключа
            KeyUsage keyUsage = recipientCertificates[i].keyUsage(); 

            // проверить допустимость использования ключа
            if (keyUsage.containsAny(KeyUsage.DECIPHER_ONLY))
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException(); 
            }
            // сохранить открытый ключ
            recipientPublicKeys[i] = recipientCertificates[i].getPublicKey(privateKey.factory()); 
        }
        // выделить память для зашифрованных ключей
		RecipientEncryptedKey[] recipientEncryptedKeys = 
			new RecipientEncryptedKey[recipientCertificates.length]; 

		// создать алгоритм согласования ключа
		try (ITransportAgreement keyAgreement = (ITransportAgreement)
            privateKey.factory().createAlgorithm(
                privateKey.scope(), parameters, ITransportAgreement.class)) 
        {
            // при ошибке выбросить исключение
            if (keyAgreement == null) throw new UnsupportedOperationException();
            
            // зашифровать ключ для получателей
            TransportAgreementData data = keyAgreement.wrap(
                privateKey, senderPublicKey, recipientPublicKeys, rand, key
            ); 
            // закодировать случайные данные
            OctetString ukm = (data.random != null) ? new OctetString(data.random) : null; 

            // для всех получателей
            for (int i = 0; i < recipientCertificates.length; i++)
            {
                // закодировать зашифрованный ключ
                recipientEncryptedKeys[i] = new RecipientEncryptedKey(
                    recipientCertificates[i].issuerSerialNumber(), 
                        new OctetString(data.encryptedKeys[i])
                ); 
            }
            // закодировать открытый ключ
            SubjectPublicKeyInfo publicKeyInfo = data.publicKey.encoded(); 
                    
            // при отсутствии указания способа идентификации
            if (senderChoice.equals(Tag.ANY)) { senderChoice = Tag.SEQUENCE; 

                // проверить допустимость способа
                if (!certificate.publicKeyInfo().equals(publicKeyInfo)) senderChoice = Tag.context(1); 
            }
            // в зависимости от способа идентификации
            if (senderChoice.equals(Tag.SEQUENCE)) 
            {
                // проверить допустимость способа
                if (!certificate.publicKeyInfo().equals(publicKeyInfo)) 
                {
                    // при ошибке выбросить исключение
                    throw new IllegalStateException();
                }
                // указать способ идентификации отправителя
                originator = certificate.issuerSerialNumber(); 
            }
            // в зависимости от способа идентификации
            else if (senderChoice.equals(Tag.context(0)))
            {
                // проверить допустимость способа
                if (!certificate.publicKeyInfo().equals(publicKeyInfo)) 
                {
                    // при ошибке выбросить исключение
                    throw new IllegalStateException();
                }
                // получить идентификатор ключа
                OctetString subjectKeyIdentifier = certificate.subjectKeyIdentifier(); 

                // проверить наличие идентификатора
                if (subjectKeyIdentifier == null) throw new UnsupportedOperationException(); 

                // закодировать идентификатор ключа
                originator = Encodable.encode(
                    senderChoice, subjectKeyIdentifier.pc(), subjectKeyIdentifier.content()
                ); 
            }
            // в зависимости от способа идентификации
            else if (senderChoice.equals(Tag.context(1)))
            {
                // указать способ идентификации отправителя
                originator = Encodable.encode(
                    senderChoice, publicKeyInfo.pc(), publicKeyInfo.content()
                ); 
            }
            // при ошибке выбросить исключение
            else throw new UnsupportedOperationException(); 

            // закодировать зашифрованный ключ с параметрами
            return new KeyAgreeRecipientInfo(
                new Integer(3), originator, ukm, parameters, 
                new RecipientEncryptedKeys(recipientEncryptedKeys)
            );
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Расшифровать ключ через алгоритм согласования
	///////////////////////////////////////////////////////////////////////
	public static int findCertificate(Certificate[] recipientCertificates, 
        KeyAgreeRecipientInfo recipientInfo) throws IOException
	{
		// получить информацию о зашифрованных ключах
		RecipientEncryptedKeys encryptedKeys = recipientInfo.recipientEncryptedKeys(); 

		// для каждого сертификата
		for (int i = 0; i < recipientCertificates.length; i++)
		{
			// извлечь проверяемый сертификат
			Certificate recipientCertificate = recipientCertificates[i]; 
            
            // проверить наличие сертификата
            if (recipientCertificate == null) continue; 

			// найти информацию о ключе 
			if (encryptedKeys.get(recipientCertificate.decoded()) != null) return i; 
		}
		return -1; 
	}
	public static ISecretKey agreementDecryptKey(IPrivateKey privateKey, 
        Certificate certificate, Certificate senderCertificate, OriginatorInfo senderInfo, 
		KeyAgreeRecipientInfo recipientInfo, SecretKeyFactory keyFactory) throws IOException
	{
		RecipientEncryptedKey encryptedKey = null; SubjectPublicKeyInfo senderPublicKeyInfo = null; 
        
        // при указании сертификата
        if (certificate != null) { KeyUsage keyUsage = certificate.keyUsage(); 

            // проверить допустимость использования ключа
            if (keyUsage.contains(KeyUsage.ENCIPHER_ONLY)) throw new IllegalStateException();
        }
		// при указании идентификатора сертификата
        if (recipientInfo.originator().tag().equals(Tag.SEQUENCE)) 
        {
            // раскодировать идентификатор сертификата
            IssuerSerialNumber certID = new IssuerSerialNumber(recipientInfo.originator()); 
            
            // при наличии сертификата отправителя
            if (senderCertificate != null)
            {
                // проверить совпадение идентификаторов сертификата
                if (!senderCertificate.decoded().tbsCertificate().issuerSerialNumber().equals(certID)) 
                {
                    // при ошибке выбросить исключение
                    throw new UnsupportedOperationException();
                }
            }
            // при наличии сертификата получателя
            else if (certificate != null)
            {
                // при совпадении идентификаторов сертификата
                if (certificate.decoded().tbsCertificate().issuerSerialNumber().equals(certID)) 
                {
                    // указать сертификат отправителя
                    senderCertificate = certificate; 
                }
            }
            // проверить наличии информации отправителя
            if (senderCertificate == null && senderInfo != null)
            {            
                // получить список сертификатов отправителя
                CertificateSet senderCertificates = senderInfo.certs();
            
                // для всех сертификатов
                if (senderCertificates != null) for (IEncodable encodable : senderCertificates)
                {
                    // проверить указание сертификата X.509
                    if (!encodable.tag().equals(Tag.SEQUENCE)) continue; 

                    // раскодировать сертификат
                    aladdin.asn1.iso.pkix.Certificate senderCert = new aladdin.asn1.iso.pkix.Certificate(encodable);

                    // проверить совпадение идентификаторов
                    if (senderCert.tbsCertificate().issuerSerialNumber().equals(certID))
                    {
                        // указать сертификат отправителя
                        senderCertificate = new Certificate(senderCert.encoded()); break; 
                    }
                }
            }
        }
		// при указании идентификатора ключа
        else if (recipientInfo.originator().tag().equals(Tag.context(0))) 
        {
            // раскодировать идентификатор ключа
            OctetString keyID = new OctetString(recipientInfo.originator()); 
            
            // при наличии сертификата отправителя
            if (senderCertificate != null)
            {
                // извлечь расширения сертификата
                Extensions extensions = senderCertificate.decoded().tbsCertificate().extensions(); 

                // получить идентификатор ключа
                OctetString id = (extensions != null) ? extensions.subjectKeyIdentifier() : null; 

                // проверить совпадение идентификатора
                if (id == null || !keyID.equals(id)) throw new UnsupportedOperationException();
            }
            // при наличии сертификата получателя
            else if (certificate != null) 
            {
                // извлечь расширения сертификата
                Extensions extensions = certificate.decoded().tbsCertificate().extensions(); 

                // получить идентификатор ключа
                OctetString id = (extensions != null) ? extensions.subjectKeyIdentifier() : null; 

                // проверить совпадение идентификатора
                if (id != null && keyID.equals(id)) { senderCertificate = certificate; }
            }
            // проверить наличии информации отправителя
            if (senderCertificate == null && senderInfo != null) 
            {
                // получить список сертификатов отправителя
                CertificateSet senderCertificates = senderInfo.certs();

                // для всех сертификатов
                if (senderCertificates != null) for (IEncodable encodable : senderCertificates)
                {
                    // проверить указание сертификата X.509
                    if (!encodable.tag().equals(Tag.SEQUENCE)) continue; 

                    // раскодировать сертификат
                    aladdin.asn1.iso.pkix.Certificate senderCert = new aladdin.asn1.iso.pkix.Certificate(encodable);

                    // извлечь расширения сертификата
                    Extensions extensions = senderCert.tbsCertificate().extensions(); 

                    // получить идентификатор ключа
                    OctetString id = (extensions != null) ? extensions.subjectKeyIdentifier() : null; 

                    // проверить совпадение идентификатора
                    if (id != null && keyID.equals(id))
                    {
                        // указать сертификат отправителя
                        senderCertificate = new Certificate(senderCert.encoded()); break; 
                    }
                }
            }
        }
        // при явном указании открытого ключа
        else if (recipientInfo.originator().tag().equals(Tag.context(1)))
        {
            // раскодировать открытый ключ 
            senderPublicKeyInfo = new SubjectPublicKeyInfo(recipientInfo.originator());

            // извлечь параметры ключа
            IEncodable keyParameters = senderPublicKeyInfo.algorithm().parameters(); 

            // при отсутствии параметров ключа
            if ((keyParameters == null || keyParameters.content().length == 0))
            {
                // при наличии сертификата отправителя
                if (senderCertificate != null)
                {
                    // закодировать открытый ключ
                    senderPublicKeyInfo = new SubjectPublicKeyInfo(
                        senderCertificate.publicKeyInfo().algorithm(), 
                        senderPublicKeyInfo.subjectPublicKey()
                    ); 
                }
                // проверить наличие сертификата получателя 
                else if (certificate != null) 
                {
                    // закодировать открытый ключ
                    senderPublicKeyInfo = new SubjectPublicKeyInfo(
                        certificate.publicKeyInfo().algorithm(), 
                        senderPublicKeyInfo.subjectPublicKey()
                    ); 
                }
            }
        }
        // при наличии сертификата отправителя
        if (senderPublicKeyInfo == null && senderCertificate != null)
        {
            // указать открытый ключ
            senderPublicKeyInfo = senderCertificate.decoded().tbsCertificate().subjectPublicKeyInfo();
        }
        // проверить наличие открытого ключа
        if (senderPublicKeyInfo == null) throw new NoSuchElementException();
        
		// раскодировать открытый ключ
		IPublicKey senderPublicKey = privateKey.factory().decodePublicKey(senderPublicKeyInfo); 
        
		// получить информацию о зашифрованных ключах
		RecipientEncryptedKeys encryptedKeys = recipientInfo.recipientEncryptedKeys(); 
        
        // при наличии сертификата
        if (certificate != null) 
        {
            // найти информацию о ключе по сертификату 
            encryptedKey = encryptedKeys.get(certificate.decoded()); 
        }
        // при наличии информации
        else if (encryptedKeys.size() == 1)
        {
            // найти информацию о ключе
            encryptedKey = encryptedKeys.get(0); 
        }
		// проверить нахождение информации о подписи 
		if (encryptedKey == null) throw new NoSuchElementException();

		// извлечь случайные данные
		byte[] random = (recipientInfo.ukm() != null) ? recipientInfo.ukm().value() : null; 

		// получить информацию об используемом алгоритме 
		AlgorithmIdentifier parameters = recipientInfo.keyEncryptionAlgorithm();

		// создать алгоритм согласования
		try (ITransportAgreement keyAgreement = (ITransportAgreement)
            privateKey.factory().createAlgorithm(
                privateKey.scope(), parameters, ITransportAgreement.class))
        {
            // при ошибке выбросить исключение
            if (keyAgreement == null) throw new UnsupportedOperationException();
            
            // вычислить ключ шифрования данных
            return keyAgreement.unwrap(privateKey, senderPublicKey, 
                random, encryptedKey.encryptedKey().value(), keyFactory
            );
        }
	}
    ///////////////////////////////////////////////////////////////////////
    // Зашифровать ключ для получателей
	///////////////////////////////////////////////////////////////////////
    public static RecipientInfos keyxEncryptKey(Factory factory, SecurityStore scope, 
        IRand rand, ISecretKey key, Certificate[] recipientCertificates, 
        AlgorithmIdentifier[] keyxParameters) throws IOException, InvalidKeyException
    {
        // создать список для зашифрованных ключей
        List<IEncodable> listRecipientInfos = new ArrayList<IEncodable>(); 

        // для каждого получателя
        for (int i = 0; i < recipientCertificates.length; i++)
        {
            // получить способ использования ключа
            KeyUsage keyUsage = recipientCertificates[i].keyUsage(); 

            // при допустимости транспорта ключа
            if (keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
            {
                // получить алгоритм транспорта ключа
                IAlgorithm algorithm = factory.createAlgorithm(
                    scope, keyxParameters[i], TransportKeyWrap.class
                );
                // при наличии алгоритма транспорта ключа
                if (algorithm != null) { RefObject.release(algorithm); 
                            
                    // зашифровать ключ шифрования данных
                    KeyTransRecipientInfo recipientInfo = CMS.transportEncryptKey(
                        factory, scope, rand, recipientCertificates[i], 
                        Tag.ANY, keyxParameters[i], key
                    );
                    // поместить зашифрованный ключ в список
                    listRecipientInfos.add(recipientInfo); continue; 
                }
            }
            // при допустимости согласования ключа
            if (keyUsage.containsAny(KeyUsage.KEY_ENCIPHERMENT | KeyUsage.KEY_AGREEMENT))
            {
                // получить алгоритм согласования ключа
                IAlgorithm algorithm = factory.createAlgorithm(
                    scope, keyxParameters[i], ITransportAgreement.class
                ); 
                // при наличии алгоритма согласования ключа
                if (algorithm != null) { RefObject.release(algorithm); 
                 
                    // извлечь открытый ключ получателя
                    IPublicKey publicKey = recipientCertificates[i].getPublicKey(factory); 

                    // создать алгорим генерации ключей
                    try (KeyPairGenerator generator = factory.createGenerator(
                        scope, rand, publicKey.keyOID(), publicKey.parameters()))
                    {  
                        // сгенерировать эфемерную пару ключей
                        try (KeyPair keyPair = generator.generate(null, publicKey.keyOID(), 
                            new KeyUsage(KeyUsage.KEY_AGREEMENT), KeyFlags.NONE))
                        {
                            // зашифровать ключ шифрования данных
                            KeyAgreeRecipientInfo recipientInfo = CMS.agreementEncryptKey(
                                rand, keyPair.privateKey, keyPair.publicKey, keyxParameters[i], 
                                new Certificate[] { recipientCertificates[i] }, key 
                            );
                            // поместить зашифрованный ключ в список
                            listRecipientInfos.add(Encodable.encode(
                                Tag.context(1), recipientInfo.pc(), recipientInfo.content()
                            ));
                            continue; 
                        }
                    }
                }
            }
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // закодировать список зашифрованных ключей
        return new RecipientInfos(listRecipientInfos.toArray(new IEncodable[0]));
    }
    public static RecipientInfos keyxEncryptKey(IRand rand, 
        IPrivateKey privateKey, Certificate certificate, ISecretKey key, 
        Certificate[] recipientCertificates, AlgorithmIdentifier[] keyxParameters, 
        OriginatorInfo[] originatorInfo) throws IOException, InvalidKeyException
    {
        // создать список для зашифрованных ключей
        List<IEncodable> listRecipientInfos = new ArrayList<IEncodable>(); originatorInfo[0] = null; 
        
        // для каждого получателя
        for (int i = 0; i < recipientCertificates.length; i++)
        {
            // получить способ использования ключа
            KeyUsage keyUsage = recipientCertificates[i].keyUsage(); 

            // при допустимости транспорта ключа
            if ((keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT)))
            {
                // получить алгоритм транспорта ключа
                IAlgorithm algorithm = privateKey.factory().createAlgorithm(
                    privateKey.scope(), keyxParameters[i], TransportKeyWrap.class
                );
                // при наличии алгоритма транспорта ключа
                if (algorithm != null) { RefObject.release(algorithm); 
                            
                    // зашифровать ключ шифрования данных
                    KeyTransRecipientInfo recipientInfo = CMS.transportEncryptKey(
                        privateKey.factory(), privateKey.scope(), rand, 
                        recipientCertificates[i], Tag.ANY, keyxParameters[i], key
                    );
                    // поместить зашифрованный ключ в список
                    listRecipientInfos.add(recipientInfo); continue; 
                }
            }
            // при допустимости согласования ключа
            if (keyUsage.containsAny(KeyUsage.KEY_ENCIPHERMENT | KeyUsage.KEY_AGREEMENT))
            {
                // получить способ использования ключа
                keyUsage = certificate.keyUsage(); 

                // проверить допустимость операции
                if (!keyUsage.containsAny(KeyUsage.KEY_ENCIPHERMENT | KeyUsage.KEY_AGREEMENT))
                {
                    // при ошибке выбросить исключение
                    throw new UnsupportedOperationException(); 
                }
                // получить алгоритм согласования ключа
                IAlgorithm algorithm = privateKey.factory().createAlgorithm(
                    privateKey.scope(), keyxParameters[i], ITransportAgreement.class
                ); 
                // при наличии алгоритма согласования ключа
                if (algorithm != null) { RefObject.release(algorithm); 

                    // указать набор сертификатов отправителя
                    CertificateSet certificates = new CertificateSet(
                        new Encodable[] { certificate.decoded() }
                    ); 
                    // указать отправителя
                    originatorInfo[0] = new OriginatorInfo(certificates, null); 
                         
                    // зашифровать ключ шифрования данных
                    KeyAgreeRecipientInfo recipientInfo = CMS.agreementEncryptKey(
                        rand, privateKey, certificate, Tag.ANY, keyxParameters[i], 
                        new Certificate[] { recipientCertificates[i] }, key 
                    );
                    // поместить зашифрованный ключ в список
                    listRecipientInfos.add(Encodable.encode(
                        Tag.context(1), recipientInfo.pc(), recipientInfo.content()
                    ));  
                    continue; 
                }
            }
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // закодировать список зашифрованных ключей
        return new RecipientInfos(listRecipientInfos.toArray(new IEncodable[0]));
    }
    ///////////////////////////////////////////////////////////////////////
    // Расшифровать ключ для получателя
	///////////////////////////////////////////////////////////////////////
	public static Certificate findCertificate(Collection<Certificate> recipientCertificates, 
        RecipientInfos recipientInfos) throws IOException
	{
		// для кажлго сертификата
		for (Certificate certificate : recipientCertificates)
		{
            // проверить наличие сертификата
            if (certificate == null) continue; 
            
			// найти информацию о ключе
			if (recipientInfos.get(certificate.decoded()) != null)
            {
                return certificate;
            }
		}
		return null; 
	}
    public static ISecretKey keyxDecryptKey(IPrivateKey privateKey, 
        Certificate certificate, Certificate senderCertificate, 
        OriginatorInfo originatorInfo, AlgorithmIdentifier parameters, 
        java.lang.Class<? extends IAlgorithm> type, IEncodable recipientInfo) throws IOException
    {
        // фабрика создания симметричных ключей
        SecretKeyFactory keyFactory = null; 
        
        // создать алгоритм шифрования
        try (IAlgorithm algorithm = privateKey.factory().createAlgorithm(
            privateKey.scope(), parameters, type))
        {
            // при ошибке выбросить исключение
            if (algorithm == null) throw new UnsupportedOperationException();
            
            // получить фабрику создания алгоритма
            if (algorithm instanceof Cipher) { keyFactory = ((Cipher)algorithm).keyFactory(); } else 
            if (algorithm instanceof Mac   ) { keyFactory = ((Mac   )algorithm).keyFactory(); } 
                
            // при ошибке выбросить исключение
            else throw new IllegalStateException(); 
            
            // в зависимости от типа дапнных
            if (recipientInfo instanceof KeyTransRecipientInfo)
            {
                // преобразовать тип данных
                KeyTransRecipientInfo keyTransRecipientInfo = 
                    (KeyTransRecipientInfo)recipientInfo; 
            
                // расшифровать ключ шифрования данных
                return CMS.transportDecryptKey(privateKey, keyTransRecipientInfo, keyFactory); 
            }
            // в зависимости от типа дапнных
            else if (recipientInfo instanceof KeyAgreeRecipientInfo)
            {
                // преобразовать тип данных
                KeyAgreeRecipientInfo keyAgreeRecipientInfo = 
                    (KeyAgreeRecipientInfo)recipientInfo; 
            
                // расшифровать ключ шифрования данных
                return CMS.agreementDecryptKey(privateKey, certificate, 
                    senderCertificate, originatorInfo, keyAgreeRecipientInfo, keyFactory
                ); 
            }
            // при ошибке выбросить исключение
            else throw new UnsupportedOperationException();
        }
    }
    ///////////////////////////////////////////////////////////////////////
	// Вычислить имитовставку через алгоритм обмена или согласования
	///////////////////////////////////////////////////////////////////////
    public static AuthenticatedData keyxMacData(Factory factory, 
        SecurityStore scope, IRand rand, Certificate[] recipientCertificates, 
		AlgorithmIdentifier[] keyxParameters, AlgorithmIdentifier macParameters, 
        AlgorithmIdentifier hashParameters, CMSData data, 
        Attributes authAttributes, Attributes unauthAttributes) throws IOException
    {
        // закодировать исходные данные
        EncapsulatedContentInfo encapContentInfo = new EncapsulatedContentInfo(
            new ObjectIdentifier(data.type), new OctetString(data.content)
        ); 
        // указать данные для имитовставки
        byte[] macData = data.content; 
        
        // при наличии защищаемых атрибутов
        if (authAttributes != null && authAttributes.size() > 0)
        {
            // проверить указание алгоритма хэширования
            if (hashParameters == null) throw new IllegalStateException(); 
            
            // создать алгоритм хэширования
            try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // при ошибке выбросить исключение
                if (hashAlgorithm == null) throw new UnsupportedOperationException();

                // захэшировать данные
                byte[] hash = hashAlgorithm.hashData(data.content, 0, data.content.length);

                // извлечь тип данных
                String dataType = encapContentInfo.eContentType().value(); 

                // указать идентификатор типа содержимого
                aladdin.asn1.Set<ObjectIdentifier> contentType = 
                    new aladdin.asn1.Set<ObjectIdentifier>(ObjectIdentifier.class, 
                        new ObjectIdentifier[] { new ObjectIdentifier(dataType) }
                );
                // указать хэш-значение
                aladdin.asn1.Set<OctetString> messageDigest = 
                    new aladdin.asn1.Set<OctetString>(OctetString.class, 
                        new OctetString[] { new OctetString(hash) }
                );
                // создать атрибут для типа содержимого
                Attribute attrContentType = new Attribute(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.CONTENT_TYPE), contentType
                ); 
                // создать атрибут для хэш-значения
                Attribute attrMessageDigest = new Attribute(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.MESSAGE_DIGEST), messageDigest
                ); 
                // выделить память для атрибутов
                List<Attribute> listAttributes = new ArrayList<Attribute>(); 

                // добавить атрибуты типа содержимого и хэш-значения
                listAttributes.add(attrContentType  ); 
                listAttributes.add(attrMessageDigest); 

                // добавить оставшиеся атрибуты в список
                for (Attribute attribute : authAttributes) listAttributes.add(attribute);

                // переустановить аутентифицируемые атрибуты
                authAttributes = new Attributes(listAttributes.toArray(new Attribute[0])); 

                // закодировать атрибуты
                macData = authAttributes.encoded(); 
            }
        }
		// создать алгоритм вычисления имитовставки
		try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
            scope, macParameters, Mac.class))
        {
            // проверить наличие алгоритма
            if (macAlgorithm == null) throw new UnsupportedOperationException();
            
            // определить допустимые размеры ключей
            int[] keySizes = macAlgorithm.keyFactory().keySizes(); 
            
            // проверить наличие только одного размера ключа
            if (keySizes == null || keySizes.length != 1) 
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException();
            }
            // преобразовать тип ключа
            try (ISecretKey key = macAlgorithm.keyFactory().generate(rand, keySizes[0])) 
            { 
                // разделить ключ между получателями
                RecipientInfos recipientInfos = keyxEncryptKey(
                    factory, scope, rand, key, recipientCertificates, keyxParameters
                ); 
                // вычислить имитовстаку
                OctetString mac = new OctetString(macAlgorithm.macData(key, macData, 0, macData.length)); 
                    
                // закодировать структуру CMS
                return new AuthenticatedData(new Integer(0), 
                    null, recipientInfos, macParameters, hashParameters, 
                    encapContentInfo, authAttributes, mac, unauthAttributes
                );
            }
            // обработать неожидаемую ошибку
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
    }
    public static AuthenticatedData keyxMacData(IRand rand, IPrivateKey privateKey, 
        Certificate certificate, Certificate[] recipientCertificates, 
		AlgorithmIdentifier[] keyxParameters, AlgorithmIdentifier macParameters, 
        AlgorithmIdentifier hashParameters, CMSData data, 
        Attributes authAttributes, Attributes unauthAttributes) throws IOException
    {
        // закодировать исходные данные
        EncapsulatedContentInfo encapContentInfo = new EncapsulatedContentInfo(
            new ObjectIdentifier(data.type), new OctetString(data.content)
        ); 
        // указать данные для имитовставки
        byte[] macData = data.content; 
        
        // при наличии защищаемых атрибутов
        if (authAttributes != null && authAttributes.size() > 0)
        {
            // проверить указание алгоритма хэширования
            if (hashParameters == null) throw new IllegalStateException(); 
            
            // создать алгоритм хэширования
            try (Hash hashAlgorithm = (Hash)privateKey.factory().createAlgorithm(
                privateKey.scope(), hashParameters, Hash.class))
            {
                // при ошибке выбросить исключение
                if (hashAlgorithm == null) throw new UnsupportedOperationException();

                // захэшировать данные
                byte[] hash = hashAlgorithm.hashData(data.content, 0, data.content.length);

                // извлечь тип данных
                String dataType = encapContentInfo.eContentType().value(); 

                // указать идентификатор типа содержимого
                aladdin.asn1.Set<ObjectIdentifier> contentType = 
                    new aladdin.asn1.Set<ObjectIdentifier>(ObjectIdentifier.class, 
                        new ObjectIdentifier[] { new ObjectIdentifier(dataType) }
                );
                // указать хэш-значение
                aladdin.asn1.Set<OctetString> messageDigest = 
                    new aladdin.asn1.Set<OctetString>(OctetString.class, 
                        new OctetString[] { new OctetString(hash) }
                );
                // создать атрибут для типа содержимого
                Attribute attrContentType = new Attribute(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.CONTENT_TYPE), contentType
                ); 
                // создать атрибут для хэш-значения
                Attribute attrMessageDigest = new Attribute(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.MESSAGE_DIGEST), messageDigest
                ); 
                // выделить память для атрибутов
                List<Attribute> listAttributes = new ArrayList<Attribute>(); 

                // добавить атрибуты типа содержимого и хэш-значения
                listAttributes.add(attrContentType  ); 
                listAttributes.add(attrMessageDigest); 

                // добавить оставшиеся атрибуты в список
                for (Attribute attribute : authAttributes) listAttributes.add(attribute);

                // переустановить аутентифицируемые атрибуты
                authAttributes = new Attributes(listAttributes.toArray(new Attribute[0])); 

                // закодировать атрибуты
                macData = authAttributes.encoded(); 
            }
        }
		// создать алгоритм вычисления имитовставки
		try (Mac macAlgorithm = (Mac)privateKey.factory().createAlgorithm(
            privateKey.scope(), macParameters, Mac.class))
        {
            // проверить наличие алгоритма
            if (macAlgorithm == null) throw new UnsupportedOperationException();
            
            // определить допустимые размеры ключей
            int[] keySizes = macAlgorithm.keyFactory().keySizes(); 
            
            // проверить наличие только одного размера ключа
            if (keySizes == null || keySizes.length != 1) 
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException();
            }
            // преобразовать тип ключа
            try (ISecretKey key = macAlgorithm.keyFactory().generate(rand, keySizes[0])) 
            { 
                // данные отправителя
                OriginatorInfo[] originatorInfo = new OriginatorInfo[1]; 
            
                // разделить ключ между получателями
                RecipientInfos recipientInfos = keyxEncryptKey(
                    rand, privateKey, certificate, key, 
                    recipientCertificates, keyxParameters, originatorInfo
                ); 
                // вычислить имитовстаку
                OctetString mac = new OctetString(macAlgorithm.macData(key, macData, 0, macData.length)); 
                    
                // установить версию структуры
                Integer version = new Integer(originatorInfo[0] != null ? 1 : 0); 
                    
                // закодировать структуру CMS
                return new AuthenticatedData(version, 
                    originatorInfo[0], recipientInfos, macParameters, hashParameters, 
                    encapContentInfo, authAttributes, mac, unauthAttributes
                );
            }
            // обработать неожидаемую ошибку
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
    }
    ///////////////////////////////////////////////////////////////////////
	// Проверить имитовставку через алгоритм обмена или согласования
	///////////////////////////////////////////////////////////////////////
	public static Certificate findCertificate(Collection<Certificate> recipientCertificates, 
        AuthenticatedData authenticatedData) throws IOException
	{
        // найти требуемый сертификат
        return findCertificate(recipientCertificates, authenticatedData.recipientInfos()); 
	}
    public static CMSData keyxVerifyMac(IPrivateKey privateKey, Certificate certificate, 
        Certificate senderCertificate, AuthenticatedData authenticatedData) throws IOException
    {
		// при наличии сертификата
		IEncodable recipientInfo = null; if (certificate != null)
		{
			// найти информацию о ключе 
			recipientInfo = authenticatedData.recipientInfos().get(certificate.decoded());
        }
		// при наличии информации
		else if (authenticatedData.recipientInfos().size() == 1)
		{
			// найти информацию 
			recipientInfo = authenticatedData.recipientInfos().get(0);
		}
		// проверить нахождение информации 
		if (recipientInfo == null) throw new NoSuchElementException();
        
		// извлечь защищаемые данные
		EncapsulatedContentInfo encapsulatedContentInfo = authenticatedData.encapContentInfo(); 

		// извлечь данные для проверки
		byte[] content = encapsulatedContentInfo.eContent().value(); 
			
		// извлечь имитовставку
		byte[] check = authenticatedData.mac().value(); byte[] hash = null;

		// определить данные для проверки имитовставки
		byte[] macData = content; byte[] hashData = null; 
        
        // извлечь защищаемые атрибуты
        Attributes authAttributes = authenticatedData.authAttrs();

        // проверить наличие атрибутов
        if (authAttributes != null && authAttributes.size() > 0) 
        {
            String contentType = null; List<Attribute> listAttributes = new ArrayList<Attribute>(); 
            
            // проверить указание алгоритма хэширования
            if (authenticatedData.digestAlgorithm() == null) throw new IOException();

            // для всех подписанных атрибутов
            for (Attribute attribute : authAttributes)
            {
                // извлечь идентификатор атрибута
                String oid = attribute.type().value(); listAttributes.add(attribute);

                // для атрибута типа данных
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.CONTENT_TYPE))
                {
                    // извлечь тип данных
                    contentType = new aladdin.asn1.Set<ObjectIdentifier>(
                        ObjectIdentifier.class, attribute.values()).get(0).value();
                }
                // для атрибута хэш-значения
                else if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.MESSAGE_DIGEST))
                {
                    // извлечь хэш-значение
                    hash = new aladdin.asn1.Set<OctetString>(
                        OctetString.class, attribute.values()).get(0).value();
                }
            }
            // проверить корректность структуры
            if (contentType == null || hash == null) throw new IOException();

            // проверить совпадение типа данных
            if (!encapsulatedContentInfo.eContentType().value().equals(contentType))
            {
                // при ошибке выбросить исключение
                throw new IOException();
            }
            // переустановить аутентифицируемые атрибуты
            authAttributes = new Attributes(listAttributes.toArray(new Attribute[0])); 
            
            // определить данные для проверки подписи
            macData = authAttributes.encoded(); hashData = content;
        }
        // получить параметры вычисления имитовставки
        AlgorithmIdentifier macParameters = authenticatedData.macAlgorithm(); 
        
		// создать алгоритм вычисления имитовставки
		try (Mac macAlgorithm = (Mac)privateKey.factory().createAlgorithm(
            privateKey.scope(), macParameters, Mac.class))
        {
            // проверить наличие алгоритма
            if (macAlgorithm == null) throw new UnsupportedOperationException();
            
            // расшифровать ключ выработки имитовставки
            try (ISecretKey key = keyxDecryptKey(privateKey, certificate, 
                senderCertificate, authenticatedData.originatorInfo(), 
                macParameters, Mac.class, recipientInfo))
            {
                // вычислить имитовставку
                byte[] mac = macAlgorithm.macData(key, macData, 0, macData.length); 
                
                // проверить совпадение имитовставок
                if (!Arrays.equals(mac, check)) throw new IOException(); 
            }
            // обработать неожидаемую ошибку
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
        // при наличии защищаемых атрибутов
        if (hashData != null && hash != null)
        {
            // создать алгоритм хэширования
            try (Hash hashAlgorithm = (Hash)privateKey.factory().createAlgorithm(
                privateKey.scope(), authenticatedData.digestAlgorithm(), Hash.class))
            {
                // проверить наличие алгоритма
                if (hashAlgorithm == null) throw new UnsupportedOperationException();

                // вычислить хэш-значение
                check = hashAlgorithm.hashData(hashData, 0, hashData.length);

                // проверить совпадение хэш-значений
                if (!Arrays.equals(hash, check)) throw new IOException();
            }
        }
        // вернуть исходные данные
        return new CMSData(encapsulatedContentInfo.eContentType().value(), content); 
    }
    ///////////////////////////////////////////////////////////////////////
	// Зашифровать данные через алгоритм обмена или согласования
	///////////////////////////////////////////////////////////////////////
    public static EnvelopedData keyxEncryptData(Factory factory, 
        SecurityStore scope, IRand rand, Certificate[] recipientCertificates, 
		AlgorithmIdentifier[] keyxParameters, AlgorithmIdentifier cipherParameters, 
        CMSData data, Attributes unprotectedAttributes) throws IOException
	{
		// создать алгоритм шифрования данных
		try (Cipher cipher = (Cipher)factory.createAlgorithm(
            scope, cipherParameters, Cipher.class))
        {
            // проверить наличие алгоритма
            if (cipher == null) throw new UnsupportedOperationException();
            
            // определить допустимые размеры ключей
            int[] keySizes = cipher.keyFactory().keySizes(); 
            
            // при нефиксированном размере ключа
            if (keySizes == null || keySizes.length != 1) 
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException();
            }
            // преобразовать тип ключа
            try (ISecretKey CEK = cipher.keyFactory().generate(rand, keySizes[0])) 
            { 
                // разделить ключ между получателями
                RecipientInfos recipientInfos = keyxEncryptKey(
                    factory, scope, rand, CEK, recipientCertificates, keyxParameters
                ); 
                // зашифровать данные
                EncryptedData encryptedData = CMS.encryptData(
                    factory, scope, CEK, cipherParameters, data, unprotectedAttributes
                );
                // закодировать структуру CMS
                return new EnvelopedData(new Integer(0), null, recipientInfos, 
                    encryptedData.encryptedContentInfo(), encryptedData.unprotectedAttrs()
                );
            }
            // обработать неожидаемую ошибку
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
	}
    public static EnvelopedData keyxEncryptData(
        IRand rand, IPrivateKey privateKey, Certificate certificate, 
        Certificate[] recipientCertificates, AlgorithmIdentifier[] keyxParameters,
        AlgorithmIdentifier cipherParameters, 
        CMSData data, Attributes attributes) throws IOException
    {
		// создать алгоритм шифрования данных
		try (Cipher cipher = (Cipher)privateKey.factory().createAlgorithm(
            privateKey.scope(), cipherParameters, Cipher.class))
        {
            // проверить наличие алгоритма
            if (cipher == null) throw new UnsupportedOperationException();
            
            // определить допустимые размеры ключей
            int[] keySizes = cipher.keyFactory().keySizes(); 
            
            // при нефиксированном размере ключа
            if (keySizes == null || keySizes.length != 1) 
            {    
                // при ошибке выбросить исключение
                throw new IllegalStateException();
            }
            // преобразовать тип ключа
            try (ISecretKey CEK = cipher.keyFactory().generate(rand, keySizes[0])) 
            { 
                // данные отправителя
                OriginatorInfo[] originatorInfo = new OriginatorInfo[1]; 
            
                // разделить ключ между получателями
                RecipientInfos recipientInfos = keyxEncryptKey(
                    rand, privateKey, certificate, CEK, 
                    recipientCertificates, keyxParameters, originatorInfo
                ); 
                // зашифровать данные
                EncryptedData encryptedData = CMS.encryptData(privateKey.factory(), 
                    privateKey.scope(), CEK, cipherParameters, data, attributes
                );
                // закодировать структуру CMS
                return new EnvelopedData(new Integer(0), originatorInfo[0], 
                    recipientInfos, encryptedData.encryptedContentInfo(), 
                    encryptedData.unprotectedAttrs()
                );
            }
            // обработать неожидаемую ошибку
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
    }
	///////////////////////////////////////////////////////////////////////
	// Расшифровать данные через алгоритм обмена
	///////////////////////////////////////////////////////////////////////
	public static Certificate findCertificate(Collection<Certificate> recipientCertificates, 
        EnvelopedData envelopedData) throws IOException
	{
        // найти требуемый сертификат
        return findCertificate(recipientCertificates, envelopedData.recipientInfos()); 
	}
	public static CMSData keyxDecryptData(IPrivateKey privateKey, Certificate certificate, 
        Certificate senderCertificate, EnvelopedData envelopedData) throws IOException
	{
		// при наличии сертификата
		IEncodable recipientInfo = null; if (certificate != null)
		{
			// найти информацию о ключе 
			recipientInfo = envelopedData.recipientInfos().get(certificate.decoded());
        }
		// при наличии информации
		else if (envelopedData.recipientInfos().size() == 1)
		{
			// найти информацию 
			recipientInfo = envelopedData.recipientInfos().get(0);
		}
		// проверить нахождение информации 
		if (recipientInfo == null) throw new NoSuchElementException();
        
        // получить параметры алгоритма шифрования
        AlgorithmIdentifier cipherParameters = 
            envelopedData.encryptedContentInfo().contentEncryptionAlgorithm(); 
        
        // расшифровать ключ шифрования данных
        try (ISecretKey CEK = keyxDecryptKey(privateKey, 
            certificate, senderCertificate, envelopedData.originatorInfo(), 
            cipherParameters, Cipher.class, recipientInfo))
        {
            // расшифровать данные
            return CMS.decryptData(privateKey.factory(), privateKey.scope(), 
                CEK, envelopedData.encryptedContentInfo(), envelopedData.unprotectedAttrs()
            ); 
        }
        // обработать неожидаемую ошибку
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
	}
	///////////////////////////////////////////////////////////////////////
	// Подписать данные
	///////////////////////////////////////////////////////////////////////
	public static SignerInfo signData(IRand rand, IPrivateKey privateKey, 
        Certificate certificate, AlgorithmIdentifier hashParameters, 
		AlgorithmIdentifier signHashParameters, 
		EncapsulatedContentInfo encapContentInfo, 
		Attributes authAttributes, Attributes unauthAttributes) throws IOException
	{
		// извлечь данные
		byte[] data = encapContentInfo.eContent().value(); 

        // создать алгоритм хэширования
		try (Hash hashAlgorithm = (Hash)privateKey.factory().
            createAlgorithm(privateKey.scope(), hashParameters, Hash.class))
        {
            // при ошибке выбросить исключение
            if (hashAlgorithm == null) throw new UnsupportedOperationException();
            
            // захэшировать данные
            byte[] hash = hashAlgorithm.hashData(data, 0, data.length);

            // при наличии подписываемых атрибутов
            if (authAttributes != null && authAttributes.size() > 0)
            {
                // извлечь тип данных
                String dataType = encapContentInfo.eContentType().value(); 

                // указать идентификатор типа содержимого
                aladdin.asn1.Set<ObjectIdentifier> contentType = 
                    new aladdin.asn1.Set<ObjectIdentifier>(ObjectIdentifier.class, 
                        new ObjectIdentifier[] { new ObjectIdentifier(dataType) }
                );
                // указать хэш-значение
                aladdin.asn1.Set<OctetString> messageDigest = 
                    new aladdin.asn1.Set<OctetString>(OctetString.class, 
                        new OctetString[] { new OctetString(hash) }
                );
                // создать атрибут для типа содержимого
                Attribute attrContentType = new Attribute(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.CONTENT_TYPE), contentType
                ); 
                // создать атрибут для хэш-значения
                Attribute attrMessageDigest = new Attribute(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.MESSAGE_DIGEST), messageDigest
                ); 
                // выделить память для атрибутов
                List<Attribute> listAttributes = new ArrayList<Attribute>(); 

                // добавить атрибуты типа содержимого и хэш-значения
                listAttributes.add(attrContentType  ); 
                listAttributes.add(attrMessageDigest); 

                // добавить оставшиеся атрибуты в список
                for (Attribute attribute : authAttributes) listAttributes.add(attribute);

                // переустановить аутентифицируемые атрибуты
                authAttributes = new Attributes(listAttributes.toArray(new Attribute[0])); 

                // закодировать атрибуты
                byte[] encoded = authAttributes.encoded(); 

                // захэшировать атрибуты
                hash = hashAlgorithm.hashData(encoded, 0, encoded.length);
            }
            // создать алгоритм подписи
            try (SignHash signAlgorithm = (SignHash)privateKey.factory().
                createAlgorithm(privateKey.scope(), signHashParameters, SignHash.class))
            {
                // при ошибке выбросить исключение
                if (signAlgorithm == null) throw new UnsupportedOperationException();
                
                // подписать хэш-значение
                OctetString signature = new OctetString(
                    signAlgorithm.sign(privateKey, rand, hashParameters, hash)
                );
                // извлечь параметры сертификата
                AlgorithmIdentifier certParameters = certificate.publicKeyInfo().algorithm(); 

                // закодировать информацию подписывающего лица
                return new SignerInfo(new Integer(1), 
                    certificate.issuerSerialNumber(), hashParameters, 
                    authAttributes, certParameters, signature, unauthAttributes
                );
            }
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Подписать данные
	///////////////////////////////////////////////////////////////////////
	public static SignedData signData(IRand rand, 
        IPrivateKey[] privateKeys, Certificate[] certificates,   
		AlgorithmIdentifier[] hashParameters, 
		AlgorithmIdentifier[] signHashParameters, CMSData data, 
		Attributes[] authAttributes, Attributes[] unauthAttributes) throws IOException
	{
		// установить версию структуры
		Integer version = new Integer(
            data.type.equals(aladdin.asn1.iso.pkcs.pkcs7.OID.DATA) ? 1 : 3
        ); 
		// закодировать подписываемые данные
		EncapsulatedContentInfo encapContentInfo = new EncapsulatedContentInfo(
            new ObjectIdentifier(data.type), new OctetString(data.content)
        ); 
		// создать список алгоритмов хэширования
		List<AlgorithmIdentifier> listHashAlgorithms = new ArrayList<AlgorithmIdentifier>();
 
        // создать список сертификатов
		List<IEncodable> listCertificates = new ArrayList<IEncodable>(); 

		// создать список подписанных данных
		List<SignerInfo> listSignerInfos = new ArrayList<SignerInfo>(); 

		// для каждого подписывающего лица
		for (int i = 0; i < privateKeys.length; i++)
		{
			// для всех алгоритмов хэширования
			boolean findHash = false; for (AlgorithmIdentifier hashAlgorithm : listHashAlgorithms)
			{
				// проверить наличие указанного алгоритма
				if (Arrays.equals(hashParameters[i].encoded(), hashAlgorithm.encoded())) { findHash = true; break; }
			}
			// добавить указанный алгоритм в список
			if (!findHash) listHashAlgorithms.add(hashParameters[i]); 
            
			// для каждого сертификата
			boolean findCert = false; for (IEncodable cert : listCertificates)
			{
				// проверить наличие указанного сертификата
				if (Arrays.equals(certificates[i].getEncoded(), cert.encoded())) { findCert = true; break; }
			}
			// добавить указанный сертификат в список
			if (!findCert) listCertificates.add(certificates[i].decoded()); 
            
			// подписать данные
			SignerInfo signerInfo = CMS.signData(rand, privateKeys[i], 
                certificates[i], hashParameters[i], signHashParameters[i], 
                encapContentInfo, authAttributes[i], unauthAttributes[i]
			); 
			// добавить подписанные данные в список
			listSignerInfos.add(signerInfo); 
		}
		// закодировать алгоритмы хэширования
		AlgorithmIdentifiers hashAlgorithms = new AlgorithmIdentifiers(
           listHashAlgorithms.toArray(new AlgorithmIdentifier[0])
        );
        // закодировать используемые сертификаты
		CertificateSet certificateSet = new CertificateSet(
            listCertificates.toArray(new IEncodable[0])
        );
		// закодировать подписанные данные из списка
		SignerInfos signerInfos = new SignerInfos(
            listSignerInfos.toArray(new SignerInfo[0])
        );
		// вернуть закодированные данные
		return new SignedData(version, hashAlgorithms, 
			encapContentInfo, certificateSet, null, signerInfos
		); 
	}
	///////////////////////////////////////////////////////////////////////
	// Проверить подпись данных
	///////////////////////////////////////////////////////////////////////
	public static Certificate findCertificate(
        Collection<Certificate> certificates, SignedData signedData)
	{
		// для кажлго сертификата
		for (Certificate certificate : certificates)
		{
            // проверить наличие сертификата
            if (certificate == null) continue; 
            
			// получить идентификатор сертификата
			IssuerSerialNumber certID = certificate.issuerSerialNumber(); 

			// при наличии идентификатора ключа
			if (certificate.subjectKeyIdentifier() != null) 
			{
				// получить идентификатор ключа
				OctetString keyID = certificate.subjectKeyIdentifier(); 

                // найти информацию о подписи по идентификатору
				if (signedData.signerInfos().get(keyID) != null) return certificate; 
			}
			// найти информацию о подписи 
			if (signedData.signerInfos().get(certID) != null) return certificate; 
		}
		return null; 
	}
	public static SignerInfo verifySign(Factory factory, 
        SecurityStore scope, Certificate certificate, SignedData signedData) 
        throws IOException, SignatureException
	{
        // извлечь открытый ключ
        IPublicKey publicKey = certificate.getPublicKey(factory); 
        
		// получить идентификатор сертификата
		IssuerSerialNumber certID = certificate.issuerSerialNumber(); 

		// при наличии идентификатора ключа
		SignerInfo signerInfo = null; if (certificate.subjectKeyIdentifier() != null) 
		{
			// получить идентификатор ключа
			OctetString keyID = certificate.subjectKeyIdentifier(); 

			// найти информацию о подписи по идентификатору
			signerInfo = signedData.signerInfos().get(keyID); 
		}
		// найти информацию о подписи 
		if (signerInfo == null) signerInfo = signedData.signerInfos().get(certID); 

		// проверить нахождение информации о подписи 
		if (signerInfo == null) throw new NoSuchElementException();

		// извлечь подписанные данные
		EncapsulatedContentInfo encapsulatedContentInfo = signedData.encapContentInfo(); 

		// извлечь данные для проверки
		byte[] content = encapsulatedContentInfo.eContent().value(); 
			
		// извлечь подпись
		byte[] signature = signerInfo.signature().value(); byte[] hash = null;

		// определить данные для проверки подписи
		byte[] signData = content; byte[] hashData = null; 

        // извлечь подписанные атрибуты
		Attributes signedAttributes = signerInfo.signedAttrs();

		// проверить наличие атрибутов
		if (signedAttributes != null && signedAttributes.size() > 0) 
		{
			String contentType = null; List<Attribute> listAttributes = new ArrayList<Attribute>(); 

			// для всех подписанных атрибутов
			for (Attribute attribute : signedAttributes)
			{
				// извлечь идентификатор атрибута
				String oid = attribute.type().value(); listAttributes.add(attribute);

				// для атрибута типа данных
				if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.CONTENT_TYPE))
				{
					// извлечь тип данных
					contentType = new aladdin.asn1.Set<ObjectIdentifier>(
                        ObjectIdentifier.class, attribute.values()).get(0).value();
				}
				// для атрибута хэш-значения
				else if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.MESSAGE_DIGEST))
				{
					// извлечь хэш-значение
					hash = new aladdin.asn1.Set<OctetString>(
                        OctetString.class, attribute.values()).get(0).value();
				}
			}
			// проверить корректность структуры
			if (contentType == null || hash == null) throw new IOException();

			// проверить совпадение типа данных
			if (!encapsulatedContentInfo.eContentType().value().equals(contentType))
			{
				// при ошибке выбросить исключение
				throw new IOException();
			}
            // переустановить аутентифицируемые атрибуты
            signedAttributes = new Attributes(listAttributes.toArray(new Attribute[0])); 
            
			// определить данные для проверки подписи
			signData = signedAttributes.encoded(); hashData = content;
		}
		// раскодировать параметры алгоритма хэширования
		AlgorithmIdentifier hashParameters = signerInfo.digestAlgorithm();

		// раскодировать параметры алгоритма подписи
		AlgorithmIdentifier signParameters = signerInfo.signatureAlgorithm();

		// создать алгоритм хэширования
		try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
        {
            // при ошибке выбросить исключение
            if (hashAlgorithm == null) throw new UnsupportedOperationException(); 
            
            // захэшировать данные
            byte[] check = hashAlgorithm.hashData(signData, 0, signData.length);

            // создать алгоритм подписи
            try (VerifyHash verifyAlgorithm = (VerifyHash)factory.createAlgorithm(
                scope, signParameters, VerifyHash.class))
            {
                // при ошибке выбросить исключение
                if (verifyAlgorithm == null) throw new UnsupportedOperationException();
                
                // проверить подпись хэш-значения
                verifyAlgorithm.verify(publicKey, hashParameters, check, signature);
			}  
            // проверить наличие атрибутов
            if (hashData != null && hash != null)
            {
                // вычислить хэш-значение
                check = hashAlgorithm.hashData(hashData, 0, hashData.length);

                // проверить совпадение хэш-значений
                if (!Arrays.equals(hash, check)) throw new SignatureException();
            }
		}
        return signerInfo;
	}
}
