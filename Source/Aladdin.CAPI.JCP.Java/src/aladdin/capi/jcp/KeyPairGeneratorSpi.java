package aladdin.capi.jcp;
import aladdin.asn1.*; 
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
	private final Provider provider; private String keyOID; private SecurityStore scope;
	// генератор случайных данных и параметры алгоритма
	private SecureRandom random; private IParameters parameters;
    
    // конструктор
	public KeyPairGeneratorSpi(Provider provider, String keyOID)
	{
        // сохранить переданные параметры
        this.provider = provider; this.keyOID = keyOID; 
        
        // получить фабрику кодирования ключей
        if (provider.factory().getKeyFactory(keyOID) == null)
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // инициализировать переменные
        this.scope = null; this.random = null; this.parameters = null; 
	}
	@Override
	public final void initialize(int keySize, SecureRandom random) 
	{
        // указать параметры ключа
        parameters = new KeyBitsParameters(keySize); this.random = random; 
	}
	@Override
	public final void initialize(AlgorithmParameterSpec paramSpec, SecureRandom random) 
		throws InvalidAlgorithmParameterException 
	{
        // сохранить генератор случайных данных
        this.random = random; if (paramSpec == null) { parameters = null; return; } 
        
        // в зависимости от типа параметров
        if (paramSpec instanceof KeyStoreParameterSpec)
        {
            // указать область видимости
            scope = ((KeyStoreParameterSpec)paramSpec).getScope(); 

            // извлечь параметры алгоритма
            paramSpec = ((KeyStoreParameterSpec)paramSpec).paramSpec();
        }
        // проверить наличие параметров
        if (paramSpec == null) { parameters = null; return; } 

        // указать фабрику кодирования
        aladdin.capi.KeyFactory keyFactory = provider.factory().getKeyFactory(keyOID); 
        try {
            // получить закодированное представление 
            AlgorithmParametersSpi parameters = provider.createParameters(keyOID, paramSpec); 
            
            // получить закодированное представление
            IEncodable encodable = parameters.getEncodable(); 
            
            // раскодировать параметры алгоритма
            this.parameters = (encodable != null) ? keyFactory.decodeParameters(encodable) : null; 
        }
        // при возникновении ошибки
        catch (InvalidParameterSpecException e)
        {
            // выбросить исключение 
            throw new InvalidAlgorithmParameterException(e.getMessage());
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
    }
	@Override
	public final java.security.KeyPair generateKeyPair() 
    {
        // проверить идентификатор ключа
        if (keyOID == null) throw new IllegalStateException();
        
        // указать фабрику кодирования
        aladdin.capi.KeyFactory keyFactory = provider.factory().getKeyFactory(keyOID); 
                
        // проверить поддержку ключа
        if (keyFactory == null) throw new UnsupportedOperationException(); 
        
        // указать способ использования ключа
        KeyUsage keyUsage = keyFactory.getKeyUsage(); 
        
        // создать объект генератора случайных данных
        try (IRand rand = provider.createRand(random))
        {
            // создать алгоритм генерации ключей
            try (aladdin.capi.KeyPairGenerator generator = provider.factory().
                createGenerator(scope, rand, keyOID, parameters))
            {
                // проверить наличие алгоритма
                if (generator == null) throw new UnsupportedOperationException(); 

                // сгенерировать ключи
                try (aladdin.capi.KeyPair keyPair = generator.generate(
                    null, keyOID, keyUsage, KeyFlags.NONE))
                {
                    // зарегистрировать личный ключ
                    java.security.PrivateKey privateKey = new PrivateKey(provider, keyPair.privateKey);
                    
                    // вернуть пару ключей
                    return new java.security.KeyPair(keyPair.publicKey, privateKey); 
                }
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidParameterException(e.getMessage()); } 
    }
}
