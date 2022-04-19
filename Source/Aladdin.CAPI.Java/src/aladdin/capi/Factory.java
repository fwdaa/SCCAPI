package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*;
import aladdin.asn1.iso.pkcs.pkcs5.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*;
import aladdin.capi.pbe.*;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Базовый класс для фабрики алгоритмов
///////////////////////////////////////////////////////////////////////////
public abstract class Factory extends RefObject
{
	// поддерживаемые фабрики кодирования ключей
	public Map<String, KeyFactory> keyFactories() 
    { 
        // поддерживаемые фабрики кодирования ключей
        return new HashMap<String, KeyFactory>(); 
    }
	// получить фабрику кодирования ключей
	public final KeyFactory getKeyFactory(String keyOID)
    {
        // получить фабрику кодирования ключей
        return keyFactories().get(keyOID); 
    }
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
    // получить идентификатор алгоритма
    public String convertAlgorithmName(String name) { return name; } 
    
	// создать алгоритм для параметров
	public final IAlgorithm createAlgorithm(
        SecurityStore scope, AlgorithmIdentifier parameters, 
        java.lang.Class<? extends IAlgorithm> type) throws IOException
    {
        // создать алгоритм для параметров
        return createAlgorithm(scope, parameters.algorithm().value(), parameters.parameters(), type); 
    }
	public IAlgorithm createAlgorithm(
        SecurityStore scope, String oid, IEncodable parameters, 
        java.lang.Class<? extends IAlgorithm> type) throws IOException
    {
        // получить идентификатор алгоритма
        oid = convertAlgorithmName(oid); 
        
        // создать алгоритм для параметров
        return createAggregatedAlgorithm(this, scope, oid, parameters, type); 
    }
	// создать алгоритм для параметров
	protected IAlgorithm createAggregatedAlgorithm(Factory outer, 
        SecurityStore scope, String oid, IEncodable parameters,
        java.lang.Class<? extends IAlgorithm> type) throws IOException
    { 
        // создать агрегированную фабрику
        try (Factory factory = AggregatedFactory.create(outer, this))
        {        
            // создать алгоритм для параметров
            return createAlgorithm(factory, scope, oid, parameters, type); 
        }
    }
	// создать алгоритм для параметров
	protected IAlgorithm createAlgorithm(Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters,
        java.lang.Class<? extends IAlgorithm> type) throws IOException
    { 
        // создать алгоритм для параметров
        return Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
    ///////////////////////////////////////////////////////////////////////
	// Создать режим блочного шифрования 
    ///////////////////////////////////////////////////////////////////////
    public final Cipher createBlockMode(SecurityStore scope, 
        String name, IEncodable parameters, byte[] iv) throws IOException
    {
        // получить позицию разделителя
        int index = name.indexOf("/"); String mode = new String(); 
        
        // извлечь имя алгоритма 
        if (index >= 0) { mode = name.substring(0, index).toUpperCase(); 
        
            // извлечь имя режима
            name = name.substring(index + 1);  
        }
        // создать блочный режим шифрования
        try (IBlockCipher blockCipher = (IBlockCipher)createAlgorithm(
            scope, name, parameters, IBlockCipher.class))
        {
            // проверить наличие алгоритма
            if (blockCipher == null) return null; 

            // определить размер блока
            int blockSize = blockCipher.blockSize(); CipherMode cipherMode = null;

            // по умолчанию
            if (mode.length() == 0 || mode.equals("NONE") || mode.equals("ECB")) 
            {
                // указать режим ECB
                cipherMode = new CipherMode.ECB(); 
            }
            // для режима CBC
            else if (mode.startsWith("CBC")) { mode = mode.substring(3); 
            
                // проверить наличие синхропосылки
                if (iv == null) throw new IllegalArgumentException(); 
              
                // прочитать размер блока для режима
                if (mode.length() != 0) { int modeBits = java.lang.Integer.parseInt(mode); 

                    // проверить корректность размера блока
                    if (modeBits == 0 || (modeBits % 8) != 0) throw new IllegalArgumentException(); 

                    // указать размер блока
                    blockSize = modeBits % 8; 
                }
                // указать используемый ражим
                cipherMode = new CipherMode.CBC(iv, blockSize); 
            }
            // для режима CFB
            else if (mode.startsWith("CFB")) { mode = mode.substring(3); 
                
                // проверить наличие синхропосылки
                if (iv == null) throw new IllegalArgumentException(); 
                
                // прочитать размер блока для режима
                if (mode.length() != 0) { int modeBits = java.lang.Integer.parseInt(mode); 

                    // проверить корректность размера блока
                    if (modeBits == 0 || (modeBits % 8) != 0) throw new IllegalArgumentException(); 

                    // указать размер блока
                    blockSize = modeBits % 8; 
                }
                // указать используемый ражим
                cipherMode = new CipherMode.CFB(iv, blockSize); 
            }
            // для режима OFB
            else if (mode.startsWith("OFB")) { mode = mode.substring(3); 
               
                // проверить наличие синхропосылки
                if (iv == null) throw new IllegalArgumentException(); 
                
                // прочитать размер блока для режима
                if (mode.length() != 0) { int modeBits = java.lang.Integer.parseInt(mode); 

                    // проверить корректность размера блока
                    if (modeBits == 0 || (modeBits % 8) != 0) throw new IllegalArgumentException(); 

                    // указать размер блока
                    blockSize = modeBits % 8; 
                }
                // указать используемый ражим
                cipherMode = new CipherMode.OFB(iv, blockSize); 
            }
            // для режима OFB
            else if (mode.startsWith("OFB")) { mode = mode.substring(3); 
                
                // проверить наличие синхропосылки
                if (iv == null) throw new IllegalArgumentException(); 
                
                // прочитать размер блока для режима
                if (mode.length() != 0) { int modeBits = java.lang.Integer.parseInt(mode); 

                    // проверить корректность размера блока
                    if (modeBits == 0 || (modeBits % 8) != 0) throw new IllegalArgumentException(); 

                    // указать размер блока
                    blockSize = modeBits % 8; 
                }
                // указать используемый ражим
                cipherMode = new CipherMode.OFB(iv, blockSize); 
            }
            // для режима CTR
            else if (mode.startsWith("CTR")) { mode = mode.substring(3); 
                
                // проверить наличие синхропосылки
                if (iv == null) throw new IllegalArgumentException(); 
                
                // прочитать размер блока для режима
                if (mode.length() != 0) { int modeBits = java.lang.Integer.parseInt(mode); 

                    // проверить корректность размера блока
                    if (modeBits == 0 || (modeBits % 8) != 0) throw new IllegalArgumentException(); 

                    // указать размер блока
                    blockSize = modeBits % 8; 
                }
                // указать используемый ражим
                cipherMode = new CipherMode.CTR(iv, blockSize); 
            }
            // режим не поддерживается
            else throw new UnsupportedOperationException(); 
             
            // создать режим блочного шифрования 
            return blockCipher.createBlockMode(cipherMode); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
	// Перенаправление алгоритмов
    ////////////////////////////////////////////////////////////////////////////
	public static IAlgorithm redirectAlgorithm(Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters,
        java.lang.Class<? extends IAlgorithm> type) throws IOException
    { 
		// для алгоритмов вычисления имитовставки
		if (type.equals(Mac.class))
		{
			if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBMAC1)) 
			{
				// раскодировать параметры алгоритма
				PBMAC1Parameter pbeParameters = new PBMAC1Parameter(parameters); 
                
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
				PBES2Parameter pbeParameters = new PBES2Parameter(parameters); 
                
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
				PBKDF2Parameter pbeParameters =	new PBKDF2Parameter(parameters); 
                
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
                scope, oid, parameters, Cipher.class))
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
			return factory.createAlgorithm(scope, oid, parameters, Encipherment.class); 
        }
		// для алгоритмов передачи ключа
		else if (type.equals(TransportKeyUnwrap.class))
		{
    		// получить алгоритм расшифрования данных
			return factory.createAlgorithm(scope, oid, parameters, Decipherment.class); 
        }
		return null; 
	}
}
