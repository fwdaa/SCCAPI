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

	// конструктор
	public KeyGeneratorSpi(Provider provider, String name) 
	{
		// сохранить переданные параметры
		this.provider = provider; Factory factory = provider.factory(); 
        
        // проверить поддержку ключа
        if (factory.getSecretKeyFactory(name) == null) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // инициализировать переменные
        this.name = name; this.random = null; this.keySize = 0;
	}
	@Override
	protected final void engineInit(int keyBits, SecureRandom random) 
	{
        // проверить поддержку размера ключа
        if ((keyBits % 8) != 0) throw new InvalidParameterException(); 
        
        // получить фабрику кодирования ключей
        SecretKeyFactory keyFactory = provider.factory().getSecretKeyFactory(name); 
        
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
        // сохранить переданные параметры
        this.random = random; this.keySize = 0; 
    }
	@Override
	protected final void engineInit(AlgorithmParameterSpec paramSpec, 
        SecureRandom random) throws InvalidAlgorithmParameterException 
	{
        // проверить указание параметров
        if (paramSpec == null) { engineInit(random); return; }
        
        // параметры генерации не поддерживаются
        throw new InvalidAlgorithmParameterException(); 
	}
	@Override
	protected final javax.crypto.SecretKey engineGenerateKey() 
	{
        // получить фабрику кодирования ключей
        SecretKeyFactory keyFactory = provider.factory().getSecretKeyFactory(name); 
        
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
