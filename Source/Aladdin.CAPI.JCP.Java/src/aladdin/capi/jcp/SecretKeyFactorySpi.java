package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.security.*;
import java.io.*;
import java.security.spec.*;
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика создания симметричных ключей
///////////////////////////////////////////////////////////////////////////////
public final class SecretKeyFactorySpi extends javax.crypto.SecretKeyFactorySpi
{
    // провайдер и имя алгоритма
    private final Provider provider; private final String name;
    
    // конструктор
    public SecretKeyFactorySpi(Provider provider, String name) 
    {  
        // сохранить переданные параметры
        this.provider = provider; this.name = name; 
    } 
    // преобразовать ключ в "родной" формат
	@Override protected final javax.crypto.SecretKey engineTranslateKey(
		javax.crypto.SecretKey key) throws InvalidKeyException 
	{
        // проверить совпадение алгоритма
        if (!key.getAlgorithm().equalsIgnoreCase(name)) throw new InvalidKeyException(); 
        
		// создать симметричный ключ
		try (ISecretKey secretKey = provider.translateSecretKey(key)) 
        {
            // зарегистрировать симметричный ключ
            return new SecretKey(provider, key.getAlgorithm(), secretKey); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }  	
	}
	@Override protected final javax.crypto.SecretKey engineGenerateSecret(KeySpec keySpec) 
		throws InvalidKeySpecException 
	{
		// проверить формат ключа
		if (keySpec instanceof SecretKeySpec) 
        {    
            // выполнить преобразование типа
            SecretKeySpec secretKeySpec = (SecretKeySpec)keySpec; 

            // проверить совпадение алгоритма
            if (!secretKeySpec.getAlgorithm().equalsIgnoreCase(name)) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeySpecException(); 
            }
            // проверить наличие значения ключа
            if (secretKeySpec.getEncoded() == null) return secretKeySpec; 
        }
        // получить фабрику кодирования ключа
        SecretKeyFactory keyFactory = provider.getSecretKeyFactory(name); 
        
        // при наличии фабрики
        if (keyFactory != null) 
        {
            // создать симметричный ключ
            try (ISecretKey secretKey = keyFactory.create(keySpec)) 
            {
                // зарегистрировать симметричный ключ
                return new SecretKey(provider, name, secretKey); 
            }
            // обработать возможную ошибку
            catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }  	
        }
        if (keySpec instanceof PBEKeySpec)
        {
            /* TODO */
        }
        throw new InvalidKeySpecException();         
	}
	@Override
    @SuppressWarnings({"unchecked", "rawtypes"}) 
	protected final KeySpec engineGetKeySpec(
        javax.crypto.SecretKey key, Class specType) throws InvalidKeySpecException 
	{
        // проверить совпадение алгоритма
        if (!key.getAlgorithm().equalsIgnoreCase(name)) throw new InvalidKeySpecException(); 
        
        // получить закодированное представление
        byte[] encoded = key.getEncoded(); if (encoded == null)
        {
            // при ошибке выбросить исключение
            throw new InvalidKeySpecException(); 
        }
        // получить фабрику кодирования ключа
        SecretKeyFactory keyFactory = provider.getSecretKeyFactory(name); 
        
        // проверить наличие фабрики
        if (keyFactory == null) throw new InvalidKeySpecException(); 
        
        // получить данные ключа
        try { return keyFactory.getSpec(name, encoded, specType); }
        
        // обработать возможное исключение
        catch (InvalidKeyException e) { throw new InvalidKeySpecException(e.getMessage()); }
	}
}
