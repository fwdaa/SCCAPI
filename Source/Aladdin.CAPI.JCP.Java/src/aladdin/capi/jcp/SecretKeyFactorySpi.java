package aladdin.capi.jcp;
import aladdin.*;
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
        
    // используемый провайдер
    public final Provider provider() { return provider; } 
    
    // преобразовать ключ в "родной" формат
	public final ISecretKey translateKey(
		javax.crypto.SecretKey key) throws InvalidKeyException 
    {
        // выполнить преобразование типа
		if (key instanceof SecretKey) { SecretKey secretKey = (SecretKey)key;

            // увеличить счетчик ссылок
            return RefObject.addRef(secretKey.get()); 
        }
		// проверить формат ключа
		if (!key.getFormat().equals("RAW")) throw new InvalidKeyException();
			
        // получить закодированное представление
        byte[] encoded = key.getEncoded(); 
        
        // проверить наличие значения
        if (encoded == null) throw new InvalidKeyException(); 
        
        // получить фабрику алгоритмов
        Factory factory = provider.getFactory(); 
        
        // указать тип ключа
        SecretKeyFactory keyFactory = factory.getSecretKeyFactory(key.getAlgorithm()); 
        
		// создать симметричный ключ
		return keyFactory.create(encoded); 
    }
    // преобразовать ключ в "родной" формат
	@Override protected final javax.crypto.SecretKey engineTranslateKey(
		javax.crypto.SecretKey key) throws InvalidKeyException 
	{
		// проверить тип ключа
		if (key instanceof SecretKey) return key; 

		// создать симметричный ключ
		try (ISecretKey secretKey = translateKey(key)) 
        {
            // зарегистрировать симметричный ключ
            return provider.registerSecretKey(secretKey); 
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
        byte[] encoded = secretKeySpec.getEncoded(); 
        
        // проверить наличие значения
        if (encoded == null) return secretKeySpec; 
        
        // получить фабрику алгоритмов
        Factory factory = provider.getFactory(); 
        
        // получить тип ключа
        SecretKeyFactory keyFactory = factory.getSecretKeyFactory(secretKeySpec.getAlgorithm());         
        
		// создать симметричный ключ
		try (ISecretKey secretKey = keyFactory.create(encoded)) 
        {
            // зарегистрировать симметричный ключ
            return provider.registerSecretKey(secretKey); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }  	
	}
	@Override
    @SuppressWarnings({"unchecked", "rawtypes"}) 
	protected final KeySpec engineGetKeySpec(
        javax.crypto.SecretKey key, Class specType) throws InvalidKeySpecException 
	{
        // получить закодированное представление
        byte[] encoded = key.getEncoded(); if (encoded == null)
        {
            // проверить тип ключа
            if (key instanceof SecretKeySpec) return (SecretKeySpec)key; 
            
            // при ошибке выбросить исключение
            throw new InvalidKeySpecException(); 
        }
        // преобразовать ключ в "родной" формат
        try (ISecretKey secretKey = translateKey(key)) 
        {
            // получить данные ключа
            return secretKey.keyFactory().getSpec(encoded, specType); 
        }
        // обработать возможное исключение
        catch (InvalidKeyException e) 
        { 
            // проверить тип ключа
            if (key instanceof SecretKeySpec) return (SecretKeySpec)key; 
            
            // при ошибке выбросить исключение
            throw new InvalidKeySpecException(e.getMessage()); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }  	
	}
}
