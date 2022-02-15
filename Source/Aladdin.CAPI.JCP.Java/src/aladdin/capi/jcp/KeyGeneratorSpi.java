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
	// провайдер и фабрика кодирования ключей
	private final Provider provider; private final SecretKeyFactory keyFactory;
	
	// датчик случайных чисел и размер ключа
	private SecureRandom random; private int keySize; 

	// конструктор
	public KeyGeneratorSpi(Provider provider, String keyType) 
	{
		// сохранить переданные параметры
		this.provider = provider; Factory factory = provider.getFactory(); 
        
        // получить фабрику кодирования ключей
        this.keyFactory = factory.getSecretKeyFactory(keyType); 
        
        // проверить поддержку ключа
        if (this.keyFactory == null) throw new UnsupportedOperationException(); 
        
        // инициализировать переменные
        this.random = null; this.keySize = 0;
	}
	@Override
	protected final void engineInit(int keyBits, SecureRandom random) 
	{
        // проверить поддержку размера ключа
        if ((keyBits % 8) != 0) throw new InvalidParameterException(); 
        
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
	protected final void engineInit(AlgorithmParameterSpec paramSpec, SecureRandom random) 
		throws InvalidAlgorithmParameterException 
	{
        // проверить указание параметров
        if (paramSpec == null) { engineInit(random); return; }
        
        // параметры генерации не поддерживаются
        throw new InvalidAlgorithmParameterException(); 
	}
	@Override
	protected final javax.crypto.SecretKey engineGenerateKey() 
	{
        // при отсутствии размера ключа
        int keyLength = keySize; if (keySize == 0) 
        {
            // получить допустимые размеры ключей
            int[] keySizes = keyFactory.keySizes(); 
        
            // проверить возможнсть выбора размера
            if (keySizes == KeySizes.UNRESTRICTED) throw new InvalidParameterException();

            // указать размер ключа по умолчанию
            if (keySize == 0) keyLength = keySizes[keySizes.length - 1]; 
        }
        // при отсутствии генератора
        if (random == null)
        {
            // создать объект ключа
            try (ISecretKey secretKey = keyFactory.generate(provider.getRand(), keyLength)) 
            {
                // зарегистрировать ключ
                return provider.registerSecretKey(secretKey); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }
        }
        // создать объект генератора
        else try (IRand rand = new Rand(random, null))
        {
            // создать объект ключа
            try (ISecretKey secretKey = keyFactory.generate(rand, keyLength))
            {
                // зарегистрировать ключ
                return provider.registerSecretKey(secretKey); 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
}
