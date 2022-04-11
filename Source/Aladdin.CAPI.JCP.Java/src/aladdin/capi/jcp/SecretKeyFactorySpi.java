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
    // конструктор
    public SecretKeyFactorySpi(Provider provider) 
     
        // сохранить переданные параметры
        { this.provider = provider; } private final Provider provider;
        
    // преобразовать ключ в "родной" формат
	@Override protected final javax.crypto.SecretKey engineTranslateKey(
		javax.crypto.SecretKey key) throws InvalidKeyException 
	{
		// проверить тип ключа
		if (key instanceof SecretKey) return key; 

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
		if (!(keySpec instanceof SecretKeySpec)) throw new InvalidKeySpecException(); 
            
        // выполнить преобразование типа
        SecretKeySpec secretKeySpec = (SecretKeySpec)keySpec; 
        
        // получить закодированное представление
        byte[] encoded = secretKeySpec.getEncoded(); if (encoded == null) return secretKeySpec; 
        
        // извлечь имя алгоритма
        String algorithm = secretKeySpec.getAlgorithm();
        
        // получить тип ключа
        SecretKeyFactory keyFactory = provider.factory().getSecretKeyFactory(algorithm);         
        
		// создать симметричный ключ
		try (ISecretKey secretKey = keyFactory.create(encoded)) 
        {
            // зарегистрировать симметричный ключ
            return new SecretKey(provider, algorithm, secretKey); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }  	
	}
	@Override
    @SuppressWarnings({"unchecked", "rawtypes"}) 
	protected final KeySpec engineGetKeySpec(
        javax.crypto.SecretKey key, Class specType) throws InvalidKeySpecException 
	{
        // при допустимом типе ключа
        if (specType.isAssignableFrom(SecretKeySpec.class))
        {
            // проверить тип ключа
            if (key instanceof SecretKeySpec) return (SecretKeySpec)key; 
        }
        // получить закодированное представление
        byte[] encoded = key.getEncoded(); if (encoded == null)
        {
            // при ошибке выбросить исключение
            throw new InvalidKeySpecException(); 
        }
        // преобразовать ключ в "родной" формат
        try (ISecretKey secretKey = provider.translateSecretKey(key)) 
        {
            // получить данные ключа
            return secretKey.keyFactory().getSpec(key.getAlgorithm(), encoded, specType); 
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
}
