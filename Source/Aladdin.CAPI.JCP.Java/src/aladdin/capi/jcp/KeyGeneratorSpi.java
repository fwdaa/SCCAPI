package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Генерация симметричных ключей
///////////////////////////////////////////////////////////////////////////////
public final class KeyGeneratorSpi extends javax.crypto.KeyGeneratorSpi
{
	// провайдер и имя алгоритма
	private final Provider provider; private final String name; 
	// генератор случайных данных и размер ключа
	private SecureRandom random; private int keySize; 
    // фабрика кодирования ключа
    private SecretKeyFactory keyFactory; 

	// конструктор
	public KeyGeneratorSpi(Provider provider, String name) 
	{
		// сохранить переданные параметры
		this.provider = provider; this.name = name; 
        
        // инициализировать переменные
        random = null; keyFactory = null; keySize = 0;
	}
	@Override
	protected final void engineInit(int keyBits, SecureRandom random) 
	{
        // проверить поддержку размера ключа
        if ((keyBits % 8) != 0) throw new InvalidParameterException(); 
        
        // получить фабрику кодирования ключа
        keyFactory = provider.getSecretKeyFactory(name); 
        
        // проверить наличие фабрики
        if (keyFactory == null) throw new IllegalStateException(); 
        
        // проверить поддержку размера ключа
        if (!KeySizes.contains(keyFactory.keySizes(), keyBits / 8))
        {
            // при ошибке выбросить исключение
            throw new InvalidParameterException(); 
        }
        // сохранить переданные параметры
        this.random = random; this.keySize = keyBits / 8; 
	}
	@Override
	protected final void engineInit(SecureRandom random) 
	{
        // получить фабрику кодирования ключа
        keyFactory = provider.getSecretKeyFactory(name); this.random = random;
        
        // проверить наличие фабрики
        if (keyFactory == null) throw new IllegalStateException(); 
    }
	@Override
	protected final void engineInit(
        AlgorithmParameterSpec paramSpec, SecureRandom random) 
            throws InvalidAlgorithmParameterException 
	{
        // сохранить генератор случайных данных
        try { this.random = random; 
            
            // получить фабрику кодирования ключа
            keyFactory = provider.getSecretKeyFactory(name, paramSpec); 
        }
        // обработать возможное исключение
        catch (InvalidParameterSpecException e) 
        { 
            // изменить тип исключения 
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }
	}
	@Override
	protected final javax.crypto.SecretKey engineGenerateKey() 
	{
        // при отсутствии размера ключа
        int keyLength = keySize; if (keyLength == 0) 
        {
            // получить допустимые размеры ключей
            int[] keySizes = keyFactory.keySizes(); 
        
            // проверить возможнсть выбора размера
            if (keySizes == KeySizes.UNRESTRICTED) throw new InvalidParameterException();

            // указать размер ключа по умолчанию
            keyLength = keySizes[keySizes.length - 1]; 
        }
        // создать объект генератора случайных данных
        try (IRand rand = provider.createRand(random))
        {
            // создать объект ключа
            try (ISecretKey secretKey = keyFactory.generate(rand, keyLength))
            {
                // зарегистрировать ключ
                return new SecretKey(provider, name, secretKey); 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
}
