package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.io.*;
import java.security.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////
// Фабрика кодирования ключей
///////////////////////////////////////////////////////////////////////////
public class KeyFactorySpi extends java.security.KeyFactorySpi
{
    // провайдер и идентификатор ключа
    private final Provider provider; private final String keyOID; 
    // фабрика кодирования ключа
    private final aladdin.capi.KeyFactory keyFactory; 
    
    // конструктор
    public KeyFactorySpi(Provider provider, String keyOID) 
    {  
        // сохранить переданные параметры
        this.provider = provider; this.keyOID = keyOID; 

        // получить фабрику кодирования
        keyFactory = provider.factory().getKeyFactory(keyOID); 

        // проверить поддержку ключа
        if (keyFactory == null) throw new UnsupportedOperationException(); 
    } 
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
            IPublicKey nativeKey = provider.translatePublicKey(publicKey); 

            // проверить совпадение идентификатора
            if (!nativeKey.keyOID().equals(keyOID)) throw new InvalidKeyException(); 
            
            return nativeKey; 
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
                // проверить совпадение идентификатора
                if (!nativeKey.keyOID().equals(keyOID)) throw new InvalidKeyException(); 
                
                // зарегистрировать личный ключ
                return new PrivateKey(provider, nativeKey); 
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
        // создать открытый ключ
        try { return keyFactory.createPublicKey(keySpec); }
            
        // при ошибке выбросить исключение
        catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
    }
    // создать личный ключ
    @Override protected java.security.PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        // создать личный ключ
        try (IPrivateKey privateKey = keyFactory.createPrivateKey(provider.factory(), keySpec)) 
        {
            // зарегистрировать личный ключ
            return new PrivateKey(provider, privateKey); 
        }
        // при ошибке выбросить исключение
        catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
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
            aladdin.capi.IPublicKey publicKey = provider.translatePublicKey((aladdin.capi.IPublicKey)key); 
            
            // проверить совпадение идентификатора
            if (!publicKey.keyOID().equals(keyOID)) throw new InvalidKeySpecException(); 

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
                // проверить совпадение идентификатора
                if (!privateKey.keyOID().equals(keyOID)) throw new InvalidKeySpecException(); 
                
                // получить данные ключа
                return (T)privateKey.keyFactory().getPrivateKeySpec(privateKey, specType); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }
        
            // обработать возможное исключение
            catch (InvalidKeyException e) { throw new InvalidKeySpecException(e.getMessage()); }
        }
        // при ошибке выбросить исключение
        throw new InvalidKeySpecException(); 
    }
}
