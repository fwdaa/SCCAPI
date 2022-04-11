package aladdin.capi.jcp;
import aladdin.capi.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import aladdin.asn1.iso.pkcs.pkcs8.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.*;

///////////////////////////////////////////////////////////////////////////
// Фабрика кодирования ключей
///////////////////////////////////////////////////////////////////////////
public class KeyFactorySpi extends java.security.KeyFactorySpi
{
    // конструктор
    public KeyFactorySpi(Provider provider) 
     
        // сохранить переданные параметры
        { this.provider = provider; } private final Provider provider;
        
    // преобразовать ключ в "родной" формат
    @Override protected java.security.Key engineTranslateKey(java.security.Key key)
        throws InvalidKeyException
    {
        // для открытого ключа
        if (key instanceof java.security.PublicKey)
        {
            // выполнить преобразование типа
            java.security.PublicKey publicKey = (java.security.PublicKey)key; 
            
            // преобразовать тип ключа
            return provider.translatePublicKey(publicKey); 
        }
        // для открытого ключа
        if (key instanceof java.security.PrivateKey)
        {
            // проверить тип ключа
            if (key instanceof PrivateKey) return key; 
            
            // выполнить преобразование типа
            java.security.PrivateKey privateKey = (java.security.PrivateKey)key; 
            
            // преобразовать тип ключа
            try (IPrivateKey nativeKey = provider.translatePrivateKey(privateKey))
            {
                // зарегистрировать личный ключ
                return new PrivateKey(provider, nativeKey); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }  	
        }
        // для симметричного ключа
        if (key instanceof javax.crypto.SecretKey)
        {
            // проверить тип ключа
            if (key instanceof SecretKey) return key; 
            
            // выполнить преобразование типа
            javax.crypto.SecretKey secretKey = (javax.crypto.SecretKey)key; 
            
            // создать симметричный ключ
            try (ISecretKey nativeKey = provider.translateSecretKey(secretKey)) 
            {
                // зарегистрировать симметричный ключ
                return new SecretKey(provider, secretKey.getAlgorithm(), nativeKey); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }  	
        }
        // при ошибке выбросить исключение
        throw new InvalidKeyException(); 
    }
    // создать открытый ключ
    @Override protected java.security.PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
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
                aladdin.capi.KeyFactory keyFactory = provider.factory().getKeyFactory(keyOID); 

                // проверить поддержку ключа
                if (keyFactory == null) throw new InvalidKeySpecException(); 

                // раскодировать открытый ключ
                return keyFactory.decodePublicKey(publicKeyInfo); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
        }
        // для всех поддерживаемых ключей
        for (aladdin.capi.KeyFactory keyFactory : provider.factory().keyFactories().values())
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
                aladdin.capi.KeyFactory keyFactory = provider.factory().getKeyFactory(keyOID); 

                // проверить поддержку ключа
                if (keyFactory == null) throw new InvalidKeySpecException(); 

                // раскодировать личный ключ
                try (IPrivateKey privateKey = keyFactory.decodePrivateKey(
                    provider.factory(), privateKeyInfo)) 
                {
                    // зарегистрировать личный ключ
                    return new PrivateKey(provider, privateKey); 
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
        }
        // для всех поддерживаемых ключей
        for (aladdin.capi.KeyFactory keyFactory : provider.factory().keyFactories().values())
        try {
            // создать личный ключ
            try (IPrivateKey privateKey = keyFactory.createPrivateKey(provider.factory(), keySpec)) 
            {
                // зарегистрировать личный ключ
                if (privateKey != null) return new PrivateKey(provider, privateKey); 
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
            try (IPrivateKey privateKey = provider.translatePrivateKey((java.security.PrivateKey)key)) 
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
            // при допустимом типе ключа
            if (specType.isAssignableFrom(SecretKeySpec.class))
            {
                // проверить тип ключа
                if (key instanceof SecretKeySpec) return (T)(SecretKeySpec)key; 
            }
            // получить закодированное представление
            byte[] encoded = key.getEncoded(); if (encoded == null)
            {
                // при ошибке выбросить исключение
                throw new InvalidKeySpecException(); 
            }
            // преобразовать ключ в "родной" формат
            try (ISecretKey secretKey = provider.translateSecretKey(
                (javax.crypto.SecretKey)key)) 
            {
                // получить данные ключа
                return (T)secretKey.keyFactory().getSpec(key.getAlgorithm(), encoded, specType); 
            }
            // обработать возможное исключение
            catch (InvalidKeyException e) 
            { 
                // при ошибке выбросить исключение
                throw new InvalidKeySpecException(e.getMessage()); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }  	
        }
        // при ошибке выбросить исключение
        throw new InvalidKeySpecException(); 
    }
}
