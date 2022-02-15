package aladdin.capi.jcp;
import aladdin.*;
import aladdin.capi.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import aladdin.asn1.iso.pkcs.pkcs8.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////
// Фабрика кодирования ключей
///////////////////////////////////////////////////////////////////////////
public class KeyFactorySpi extends java.security.KeyFactorySpi
{
    // фабрика создания симметричных ключей
    private final SecretKeyFactorySpi secretKeyFactory; 
    
    // конструктор
    public KeyFactorySpi(Provider provider) 
    { 
        // сохранить переданные параметры
        secretKeyFactory = new SecretKeyFactorySpi(provider); 
    } 
    // преобразовать открытый ключ в "родной" формат
    public IPublicKey translatePublicKey(java.security.PublicKey key) throws InvalidKeyException
    {
        // проверить тип ключа
        if (key instanceof IPublicKey) return (IPublicKey)key; 
            
        // получить закодированное представление ключа
        byte[] encoded = key.getEncoded(); if (encoded == null)
        {
            // проверить наличие представления
            throw new InvalidKeyException();
        }
        // проверить формат данных
        if (!key.getFormat().equals("X.509")) throw new InvalidKeyException(); 

        // получить фабрику алгоритмов
        Factory factory = secretKeyFactory.provider().getFactory(); 
        try { 
            // раскодировать данные
            SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(
                Encodable.decode(encoded)
            ); 
            // извлечь идентификатор открытого ключа
            String keyOID = publicKeyInfo.algorithm().algorithm().value(); 

            // получить фабрику кодирования
            aladdin.capi.KeyFactory keyFactory = factory.getKeyFactory(keyOID); 

            // проверить поддержку ключа
            if (keyFactory == null) throw new InvalidKeyException(); 

            // раскодировать открытый ключ
            return keyFactory.decodePublicKey(publicKeyInfo); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }
    }
    // преобразовать личный ключ в "родной" формат
    public IPrivateKey translatePrivateKey(java.security.PrivateKey key) throws InvalidKeyException
    {
        // выполнить преобразование типа
		if (key instanceof PrivateKey) { PrivateKey privateKey = (PrivateKey)key;

            // увеличить счетчик ссылок
            return RefObject.addRef(privateKey.get()); 
        }
        // получить закодированное представление ключа
        byte[] encoded = key.getEncoded(); if (encoded == null)
        {
            // проверить наличие представления
            throw new InvalidKeyException();
        }
        // проверить формат данных
        if (!key.getFormat().equals("PKCS#8")) throw new InvalidKeyException(); 

        // получить фабрику алгоритмов
        Factory factory = secretKeyFactory.provider().getFactory(); 
        try { 
            // раскодировать данные
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
                Encodable.decode(encoded)
            ); 
            // извлечь идентификатор открытого ключа
            String keyOID = privateKeyInfo.privateKeyAlgorithm().algorithm().value(); 

            // получить фабрику кодирования
            aladdin.capi.KeyFactory keyFactory = factory.getKeyFactory(keyOID); 

            // проверить поддержку ключа
            if (keyFactory == null) throw new InvalidKeyException(); 

            // раскодировать личный ключ
            return keyFactory.decodePrivateKey(factory, privateKeyInfo);
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }
    }
    // преобразовать ключ в "родной" формат
    @Override protected java.security.Key engineTranslateKey(java.security.Key key)
        throws InvalidKeyException
    {
        // получить используемый провайдер
        Provider provider = secretKeyFactory.provider(); 
        
        // для открытого ключа
        if (key instanceof java.security.PublicKey)
        {
            // преобразовать тип ключа
            return translatePublicKey((java.security.PublicKey)key); 
        }
        // для открытого ключа
        if (key instanceof java.security.PrivateKey)
        {
            // проверить тип ключа
            if (key instanceof PrivateKey) return key; 
            
            // преобразовать тип ключа
            try (IPrivateKey privateKey = translatePrivateKey((java.security.PrivateKey)key)) 
            {
                // зарегистрировать личный ключ
                return provider.registerPrivateKey(privateKey); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }  	
        }
        // для симметричного ключа
        if (key instanceof javax.crypto.SecretKey)
        {
            // выполнить преобразование типа
            javax.crypto.SecretKey secretKey = (javax.crypto.SecretKey)key; 
            
            // преобразовать ключ в "родной" формат
            return secretKeyFactory.engineTranslateKey(secretKey); 
        }
        // при ошибке выбросить исключение
        throw new InvalidKeyException(); 
    }
    // создать открытый ключ
    @Override protected java.security.PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        // получить фабрику алгоритмов
        Factory factory = secretKeyFactory.provider().getFactory(); 
        
        // в зависимости от типа данных
        if (keySpec instanceof EncodedKeySpec)
        {
            // выполнить преобразование типа
            EncodedKeySpec encodedKeySpec = (EncodedKeySpec)keySpec; 

            // проверить формат данных
            if (!encodedKeySpec.getFormat().equals("X.509")) throw new InvalidKeySpecException(); 
            try { 
                // раскодировать данные
                SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(
                    Encodable.decode(encodedKeySpec.getEncoded())
                ); 
                // извлечь идентификатор открытого ключа
                String keyOID = publicKeyInfo.algorithm().algorithm().value(); 

                // получить фабрику кодирования
                aladdin.capi.KeyFactory keyFactory = factory.getKeyFactory(keyOID); 

                // проверить поддержку ключа
                if (keyFactory == null) throw new InvalidKeySpecException(); 

                // раскодировать открытый ключ
                return keyFactory.decodePublicKey(publicKeyInfo); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
        }
        // для всех поддерживаемых ключей
        for (aladdin.capi.KeyFactory keyFactory : factory.keyFactories())
        try {
            // создать открытый ключ
            aladdin.capi.IPublicKey publicKey = keyFactory.createPublicKey(keySpec); 
            
            // проверить создание ключа
            if (publicKey != null) return publicKey; 
        }
        // при ошибке выбросить исключение
        catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
        
        // при ошибке выбросить исключение
        throw new InvalidKeySpecException(); 
    }
    // создать личный ключ
    @Override protected java.security.PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        // получить используемый провайдер
        Provider provider = secretKeyFactory.provider(); Factory factory = provider.getFactory(); 
        
        // в зависимости от типа данных
        if (keySpec instanceof EncodedKeySpec)
        { 
            // выполнить преобразование типа
            EncodedKeySpec encodedKeySpec = (EncodedKeySpec)keySpec; 
            
            // проверить формат данных
            if (!encodedKeySpec.getFormat().equals("PKCS#8")) throw new InvalidKeySpecException(); 
            try { 
                // раскодировать данные
                PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
                    Encodable.decode(encodedKeySpec.getEncoded())
                ); 
                // извлечь идентификатор открытого ключа
                String keyOID = privateKeyInfo.privateKeyAlgorithm().algorithm().value(); 

                // получить фабрику кодирования
                aladdin.capi.KeyFactory keyFactory = factory.getKeyFactory(keyOID); 

                // проверить поддержку ключа
                if (keyFactory == null) throw new InvalidKeySpecException(); 

                // раскодировать личный ключ
                try (IPrivateKey privateKey = keyFactory.decodePrivateKey(factory, privateKeyInfo)) 
                {
                    // зарегистрировать личный ключ
                    return provider.registerPrivateKey(privateKey); 
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
        }
        // для всех поддерживаемых ключей
        for (aladdin.capi.KeyFactory keyFactory : factory.keyFactories())
        try {
            // создать личный ключ
            try (aladdin.capi.IPrivateKey privateKey = keyFactory.createPrivateKey(factory, keySpec)) 
            {
                // зарегистрировать личный ключ
                if (privateKey != null) return provider.registerPrivateKey(privateKey); 
            }
        }
        // при ошибке выбросить исключение
        catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
        
        // при ошибке выбросить исключение
        throw new InvalidKeySpecException(); 
    }
    // получить данные ключа
    @SuppressWarnings({"unchecked"}) 
    @Override protected <T extends KeySpec>
        T engineGetKeySpec(java.security.Key key, Class<T> specType)
        throws InvalidKeySpecException
    {
        // для открытого ключа
        if (key instanceof java.security.PublicKey)
        try {
            // преобразовать тип ключа
            aladdin.capi.IPublicKey publicKey = (aladdin.capi.IPublicKey)engineTranslateKey(key); 

            // получить данные ключа
            return (T)publicKey.keyFactory().getPublicKeySpec(publicKey, specType); 
        }
        // обработать возможное исключение
        catch (InvalidKeyException e) { throw new InvalidKeySpecException(e.getMessage()); }
        
        // для личного ключа
        if (key instanceof java.security.PrivateKey)
        {
            // выполнить преобразование типа
            try (IPrivateKey privateKey = translatePrivateKey((java.security.PrivateKey)key)) 
            { 
                // получить данные ключа
                return (T)privateKey.keyFactory().getPrivateKeySpec(privateKey, specType); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
        
            // обработать возможное исключение
            catch (InvalidKeyException e) { throw new InvalidKeySpecException(e.getMessage()); }
        }
        // для симметричного ключа
        if (key instanceof javax.crypto.SecretKey)
        {
            // выполнить преобразование типа
            javax.crypto.SecretKey secretKey = (javax.crypto.SecretKey)key; 
            
            // получить данные ключа
            return (T)secretKeyFactory.engineGetKeySpec(secretKey, specType); 
        }
        // при ошибке выбросить исключение
        throw new InvalidKeySpecException(); 
    }
}
