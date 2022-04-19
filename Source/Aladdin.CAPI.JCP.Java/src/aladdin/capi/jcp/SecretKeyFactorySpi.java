package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.security.*;
import java.io.*;
import java.security.spec.*;
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика создания симметричных ключей
///////////////////////////////////////////////////////////////////////////////
public class SecretKeyFactorySpi extends javax.crypto.SecretKeyFactorySpi
{
    // провайдер и имя алгоритма
    private final Provider provider; private final String name;
    
    // конструктор
    public SecretKeyFactorySpi(Provider provider, String name) 
    {  
        // сохранить переданные параметры
        this.provider = provider; this.name = name; 
    } 
    // используемый провайдер
    protected final Provider getProvider() { return provider; }
    // имя алгоритма
    protected final String getAlgorithm() { return name; }
    
    // преобразовать ключ в "родной" формат
	@Override protected final javax.crypto.SecretKey engineTranslateKey(
		javax.crypto.SecretKey key) throws InvalidKeyException 
	{
		// создать симметричный ключ
		try (ISecretKey secretKey = provider.translateSecretKey(key)) 
        {
            // зарегистрировать симметричный ключ
            return new SecretKey(provider, name, secretKey); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }  	
	}
	@Override protected javax.crypto.SecretKey engineGenerateSecret(KeySpec keySpec) 
		throws InvalidKeySpecException 
	{
		// проверить формат ключа
		if (!(keySpec instanceof SecretKeySpec)) throw new InvalidKeySpecException();
        
        // получить фабрику кодирования ключа
        SecretKeyFactory keyFactory = provider.getSecretKeyFactory(name); 

        // проверить наличии фабрики
        if (keyFactory == null) throw new InvalidKeySpecException();
        
        // создать симметричный ключ
        try (ISecretKey secretKey = keyFactory.create(keySpec)) 
        {
            // зарегистрировать симметричный ключ
            return new SecretKey(provider, name, secretKey); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new InvalidKeySpecException(e.getMessage()); }  	
	}
	@Override
    @SuppressWarnings({"unchecked"}) 
	protected final KeySpec engineGetKeySpec(
        javax.crypto.SecretKey key, Class<?> specType) throws InvalidKeySpecException 
	{
        // проверить корректность параметров
        if (!KeySpec.class.isAssignableFrom(specType)) throw new InvalidKeySpecException(); 
        
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
        try { return keyFactory.getSpec(name, encoded, (Class<? extends KeySpec>)specType); }
        
        // обработать возможное исключение
        catch (InvalidKeyException e) { throw new InvalidKeySpecException(e.getMessage()); }
	}
}
