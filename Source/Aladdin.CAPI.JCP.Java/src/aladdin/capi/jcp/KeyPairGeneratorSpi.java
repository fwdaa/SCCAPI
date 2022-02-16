package aladdin.capi.jcp;
import aladdin.*;
import aladdin.asn1.iso.*; 
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
	private final Provider provider; private String keyOID; 
    
	// параметры алгоритма и генератор случайных данных
	private IParameters parameters; private SecureRandom random;
    
    // конструктор
	public KeyPairGeneratorSpi(Provider provider, String keyOID)
	{
        // сохранить переданные параметры
        this.provider = provider; this.keyOID = keyOID; 
        
        // получить фабрику кодирования ключей
        if (keyOID != null && provider.getFactory().getKeyFactory(keyOID) == null)
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // инициализировать переменные
        this.parameters = null; this.random = null;
	}
	@Override
	public final void initialize(int keySize, SecureRandom random) 
	{
        // проверить идентификатор ключа
        if (keyOID == null || !keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException();
        } 
        // указать параметры ключа
        parameters = new aladdin.capi.ansi.rsa.Parameters(keySize, null); 
	}
	@Override
	public final void initialize(AlgorithmParameterSpec paramSpec, SecureRandom random) 
		throws InvalidAlgorithmParameterException 
	{
        // сохранить генератор случайных данных
        Factory factory = provider.getFactory(); this.random = random; 
		try {
            // проверить наличие параметров
			if (paramSpec == null && keyOID == null) throw new InvalidAlgorithmParameterException(); 
            
            // указать отсутствие параметров
            if (paramSpec == null) this.parameters = null; 
            else {
                // преобразовать тип параметров
                AlgorithmParametersSpi parameters = AlgorithmParametersSpi.create(provider, paramSpec);
                
                // получить закодированное представление 
                AlgorithmIdentifier encodable = parameters.getEncodable(); 
                
                // при указании идентификатора ключа
                if (keyOID != null && !keyOID.equals(encodable.algorithm().value())) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidAlgorithmParameterException(); 
                }
                // указать идентификатор ключа
                this.keyOID = encodable.algorithm().value(); 
                
                // указать фабрику кодирования
                aladdin.capi.KeyFactory keyFactory = factory.getKeyFactory(keyOID); 
                
                // проверить поддержку ключа
                if (keyFactory == null) throw new UnsupportedOperationException(); 
                try {         
                    // раскодировать параметры алгоритма
                    this.parameters = keyFactory.decodeParameters(encodable.parameters()); 
                }
                // обработать возможное исключение
                catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
            } 
        }
        // при возникновении ошибки
        catch (InvalidParameterSpecException e)
        {
            // выбросить исключение 
            throw new InvalidAlgorithmParameterException(e.getMessage());
        }
    }
	@Override
	public final java.security.KeyPair generateKeyPair() 
    {
        // указать фабрику кодирования
        aladdin.capi.KeyFactory keyFactory = provider.getFactory().getKeyFactory(keyOID); 
                
        // проверить поддержку ключа
        if (keyFactory == null) throw new UnsupportedOperationException(); 
        
        // указать способ использования ключа
        KeyUsage keyUsage = keyFactory.getKeyUsage(); 
        
        // при отсутствии генератора
        Factory factory = provider.getFactory(); if (random == null)
        {
            // создать алгоритм генерации ключей
            try (aladdin.capi.KeyPairGenerator generator = factory.createGenerator(
                null, provider.getRand(), keyOID, parameters))
            {
                // проверить наличие алгоритма
                if (generator == null) throw new UnsupportedOperationException(); 
                
                // сгенерировать ключи
                try (aladdin.capi.KeyPair keyPair = generator.generate(
                    null, keyOID, keyUsage, KeyFlags.NONE))
                {
                    // зарегистрировать личный ключ
                    java.security.PrivateKey privateKey = provider.registerPrivateKey(keyPair.privateKey);
                    
                    // вернуть пару ключей
                    return new java.security.KeyPair(keyPair.publicKey, privateKey); 
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidParameterException(e.getMessage()); } 
        }
        // указать генератор случайных данных
        else try (IRand rand = new Rand(random, null))
        {
            // создать алгоритм генерации ключей
            try (aladdin.capi.KeyPairGenerator generator = factory.createGenerator(
                null, rand, keyOID, parameters))
            {
                // проверить наличие алгоритма
                if (generator == null) throw new UnsupportedOperationException(); 

                // сгенерировать ключи
                try (aladdin.capi.KeyPair keyPair = generator.generate(
                    null, keyOID, keyUsage, KeyFlags.NONE))
                {
                    // зарегистрировать личный ключ
                    java.security.PrivateKey privateKey = provider.registerPrivateKey(keyPair.privateKey);
                    
                    // вернуть пару ключей
                    return new java.security.KeyPair(keyPair.publicKey, privateKey); 
                }
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidParameterException(e.getMessage()); } 
    }
}
