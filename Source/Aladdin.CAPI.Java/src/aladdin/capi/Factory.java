package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.pkcs5.*; 
import aladdin.asn1.iso.pkcs.pkcs8.PrivateKeyInfo;
import aladdin.asn1.iso.pkix.SubjectPublicKeyInfo;
import aladdin.capi.pbe.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Базовый класс для фабрики алгоритмов
///////////////////////////////////////////////////////////////////////////
public abstract class Factory extends RefObject
{
	// получить фабрику кодирования ключей
	public final SecretKeyFactory getSecretKeyFactory(String name)
    {
        // для всех фабрик ключей
        for (SecretKeyFactory keyFactory : secretKeyFactories())
        {
            // для всех поддерживаемых имен
            for (String keyName : keyFactory.names())
            {
                // сравнить имя ключа
                if (keyName.compareToIgnoreCase(name) == 0) return keyFactory; 
            }
        }
        // получить фабрику кодирования ключей
        return SecretKeyFactory.GENERIC; 
    }
	// поддерживаемые фабрики кодирования ключей
	public SecretKeyFactory[] secretKeyFactories() { return new SecretKeyFactory[0]; }
    
	// получить фабрику кодирования ключей
	public final KeyFactory getKeyFactory(String keyOID)
    {
        // для всех фабрик ключей
        for (KeyFactory keyFactory : keyFactories())
        {
            // проверить наличие ключа
            if (keyOID.equals(keyFactory.keyOID())) return keyFactory; 
        }
        return null; 
    }
	// поддерживаемые фабрики кодирования ключей
	public KeyFactory[] keyFactories() { return new KeyFactory[0]; }
    
	// раскодировать открытый ключ
	public final IPublicKey decodePublicKey(
		SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException
	{
		// получить параметры алгоритма
		AlgorithmIdentifier algorithmParameters = subjectPublicKeyInfo.algorithm(); 
        
        // указать идентификатор ключа
        String keyOID = algorithmParameters.algorithm().value(); 

		// получить фабрику ключей
		KeyFactory keyFactory = getKeyFactory(keyOID);
 
		// проверить наличие фабрики ключей
		if (keyFactory == null) throw new UnsupportedOperationException();
        
		// раскодировать открытый ключ
		return keyFactory.decodePublicKey(subjectPublicKeyInfo); 
	}
	// Раскодировать личный ключ
	public final IPrivateKey decodePrivateKey(PrivateKeyInfo privateKeyInfo) throws IOException
	{
		// получить параметры алгоритма
		AlgorithmIdentifier algorithmParameters = privateKeyInfo.privateKeyAlgorithm(); 

		// получить фабрику ключей
		KeyFactory keyFactory = getKeyFactory(algorithmParameters.algorithm().value());
        
		// проверить наличие фабрики ключей
		if (keyFactory == null) throw new UnsupportedOperationException();
 
		// раскодировать личный ключ
		return keyFactory.decodePrivateKey(this, privateKeyInfo); 
	}
	// раскодировать пару ключей
	public final KeyPair decodeKeyPair(PrivateKeyInfo privateKeyInfo) throws IOException
	{
		// получить параметры алгоритма
		AlgorithmIdentifier algorithmParameters = privateKeyInfo.privateKeyAlgorithm(); 

        // извлечь идентификатор ключа
        String keyOID = algorithmParameters.algorithm().value(); 

		// получить фабрику ключей
		KeyFactory keyFactory = getKeyFactory(keyOID);
 
		// проверить наличие фабрики ключей
		if (keyFactory == null) throw new UnsupportedOperationException();
 
		// раскодировать личный ключ
		return keyFactory.decodeKeyPair(this, privateKeyInfo); 
	}
	// создать алгоритм генерации ключей
	public KeyPairGenerator createGenerator(SecurityObject scope, 
        IRand rand, String keyOID, IParameters parameters) throws IOException 
    { 
        // создать алгоритм генерации ключей
        return createAggregatedGenerator(this, scope, rand, keyOID, parameters); 
    }
	// создать алгоритм генерации ключей
	protected KeyPairGenerator createAggregatedGenerator(
        Factory outer, SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException 
    { 
        // создать агрегированную фабрику
        try (Factory factory = AggregatedFactory.create(outer, this))
        {       
            // создать алгоритм генерации ключей
            return createGenerator(factory, scope, rand, keyOID, parameters); 
        }
    }
	// создать алгоритм генерации ключей
	protected KeyPairGenerator createGenerator(
        Factory factory, SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException { return null; }
    
	// сгенерировать ключи
	public final KeyPair generateKeyPair(SecurityObject scope, 
        IRand rand, byte[] keyID, String keyOID, IParameters parameters, 
        KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
        // создать генератор ключей
        try (KeyPairGenerator generator = createGenerator(scope, rand, keyOID, parameters)) 
        {
            // проверить наличие генератора
            if (generator == null) throw new UnsupportedOperationException();

            // сгенерировать ключи
            return generator.generate(keyID, keyOID, keyUsage, keyFlags); 
        }
	}
	// создать алгоритм для параметров
	public IAlgorithm createAlgorithm(
        SecurityStore scope, AlgorithmIdentifier parameters, 
        java.lang.Class<? extends IAlgorithm> type) throws IOException
    {
        // создать алгоритм для параметров
        return createAggregatedAlgorithm(this, scope, parameters, type); 
    }
	// создать алгоритм для параметров
	protected IAlgorithm createAggregatedAlgorithm(Factory outer, 
        SecurityStore scope, AlgorithmIdentifier parameters, 
        java.lang.Class<? extends IAlgorithm> type) throws IOException
    { 
        // создать агрегированную фабрику
        try (Factory factory = AggregatedFactory.create(outer, this))
        {        
            // создать алгоритм для параметров
            return createAlgorithm(factory, scope, parameters, type); 
        }
    }
	// создать алгоритм для параметров
	protected IAlgorithm createAlgorithm(Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters, 
        java.lang.Class<? extends IAlgorithm> type) throws IOException
    { 
        // создать алгоритм для параметров
        return Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
    ////////////////////////////////////////////////////////////////////////////
	// Перенаправление алгоритмов
    ////////////////////////////////////////////////////////////////////////////
	public static IAlgorithm redirectAlgorithm(Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters, 
        java.lang.Class<? extends IAlgorithm> type) throws IOException
    { 
		// определить идентификатор алгоритма
		String oid = parameters.algorithm().value(); 

		// для алгоритмов вычисления имитовставки
		if (type.equals(Mac.class))
		{
			if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBMAC1)) 
			{
				// раскодировать параметры алгоритма
				PBMAC1Parameter pbeParameters = new PBMAC1Parameter(parameters.parameters()); 
                
                // создать алгоритм вычисления имитовставки
                try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                    scope, pbeParameters.messageAuthScheme(), Mac.class))
                {
                    // проверить наличие алгоритма
                    if (macAlgorithm == null) return null; 

                    // создать алгоритм наследования ключа по паролю
                    try (KeyDerive derivationAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, pbeParameters.keyDerivationFunc(), KeyDerive.class))
                    {
                        // проверить наличие алгоритма
                        if (derivationAlgorithm == null) return null; 

                        // создать алгоритм вычисления имитовставки по паролю
                        return new PBMAC1(derivationAlgorithm, macAlgorithm); 
                    }
                }
			}
		}
		// для алгоритмов симметричного шифрования
		else if (type.equals(Cipher.class))
		{
			if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBES2)) 
			{
				// раскодировать параметры алгоритма
				PBES2Parameter pbeParameters = new PBES2Parameter(parameters.parameters()); 
                
                // создать алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, pbeParameters.encryptionScheme(), Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 

                    // создать алгоритм наследования ключа по паролю
                    try (KeyDerive derivationAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, pbeParameters.keyDerivationFunc(), KeyDerive.class))
                    {
                        // проверить наличие алгоритма
                        if (derivationAlgorithm == null) return null; 

                        // создать алгоритм шифрования по паролю
                        return new PBES2(derivationAlgorithm, cipher);  
                    }
                }
            }
		}
		// для алгоритмов наследования ключа
		else if (type.equals(KeyDerive.class))
		{
			if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBKDF2)) 
			{
				// раскодировать параметры алгоритма
				PBKDF2Parameter pbeParameters =	new PBKDF2Parameter(parameters.parameters()); 
                
                // при указании размера ключа
                int keySize = -1; if (pbeParameters.keyLength() != null)
                {
                    // прочитать размер ключа
                    keySize = pbeParameters.keyLength().value().intValue();
                }
                // извлечь salt-значение
                OctetString salt = new OctetString(pbeParameters.salt());  

                // создать алгоритм вычисления имитовставки
                try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                    scope, pbeParameters.prf(), Mac.class))
                {
                    // проверить наличие алгоритма
                    if (macAlgorithm == null) return null; 

                    // создать алгоритм наследования ключа
                    return new PBKDF2(macAlgorithm, salt.value(), 
                        pbeParameters.iterationCount().value().intValue(), keySize
                    );
                }
			}
		}
		// для алгоритмов шифрования ключа
		else if (type.equals(KeyWrap.class))
		{
            // получить алгоритм шифрования данных
            try (Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, parameters, Cipher.class))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                    
                // вернуть алгоритм шифрования ключа
                return cipher.createKeyWrap(PaddingMode.PKCS5); 
            }
        }
		// для алгоритмов передачи ключа
		else if (type.equals(TransportKeyWrap.class))
		{
    		// получить алгоритм зашифрования данных
			return factory.createAlgorithm(scope, parameters, Encipherment.class); 
        }
		// для алгоритмов передачи ключа
		else if (type.equals(TransportKeyUnwrap.class))
		{
    		// получить алгоритм расшифрования данных
			return factory.createAlgorithm(scope, parameters, Decipherment.class); 
        }
		return null; 
	}
}
