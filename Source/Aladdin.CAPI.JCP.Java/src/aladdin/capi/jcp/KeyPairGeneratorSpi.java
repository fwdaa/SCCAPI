package aladdin.capi.jcp;
import aladdin.capi.jcp.params.*; 
import aladdin.capi.*; 
import java.io.*;
import java.security.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм генерации асимметричных ключей
///////////////////////////////////////////////////////////////////////////////
public final class KeyPairGeneratorSpi extends java.security.KeyPairGeneratorSpi
{
    // используемый провайдер и идентификатор ключа
	private final Provider provider; private final String keyOID; private final KeyUsage keyUsage; 
	// параметры алгоритма и генератор случайных данных
	private final AlgorithmParameters parameters; private SecureRandom random; 
    
    // конструктор
	public KeyPairGeneratorSpi(Provider provider, String keyOID)
	{
        // сохранить переданные параметры
        this.provider = provider; this.keyOID = keyOID; 
        
        // получить фабрику кодирования ключей
        aladdin.capi.KeyFactory keyFactory = provider.factory().getKeyFactory(keyOID); 
        
        // проверить наличие фабрики
        if (keyFactory == null) throw new UnsupportedOperationException();
        
        // инициализировать переменные
        parameters = new AlgorithmParameters(new KeyParameters(provider, keyOID)); 
        
        // получить способ использования ключей
        keyUsage = keyFactory.getKeyUsage(); random = null; 
	}
	@Override
	public final void initialize(int keySize, SecureRandom random) 
	{
        // инициализировать параметры алгоритма
        try { parameters.init(new KeySizeParameterSpec(keySize)); this.random = random; }
        
        // обработать возможное исключение
        catch (InvalidParameterSpecException e) { throw new RuntimeException(e); }
	}
	@Override
	public final void initialize(AlgorithmParameterSpec paramSpec, SecureRandom random) 
		throws InvalidAlgorithmParameterException 
	{
        // инициализировать параметры алгоритма
        try { parameters.init(paramSpec); this.random = random; }
        
        // при возникновении исключения 
        catch (InvalidParameterSpecException e) 
        { 
            // преобразовать тип исключения 
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }
    }
	@Override
	public final java.security.KeyPair generateKeyPair() 
    {
        // создать алгоритм генерации ключей
        try (aladdin.capi.KeyPairGenerator generator = provider.createGenerator(keyOID, parameters, random))
        {
            // проверить наличие алгоритма
            if (generator == null) throw new UnsupportedOperationException(); 

            // сгенерировать ключи
            try (aladdin.capi.KeyPair keyPair = generator.generate(null, keyOID, keyUsage, KeyFlags.NONE))
            {
                // зарегистрировать личный ключ
                java.security.PrivateKey privateKey = new PrivateKey(provider, keyPair.privateKey);
                    
                // вернуть пару ключей
                return new java.security.KeyPair(keyPair.publicKey, privateKey); 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidParameterException(e.getMessage()); } 
    }
}
