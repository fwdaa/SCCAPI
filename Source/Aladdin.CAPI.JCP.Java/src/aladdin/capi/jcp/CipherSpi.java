package aladdin.capi.jcp;
import aladdin.*;
import aladdin.asn1.*;
import aladdin.capi.*; 
import aladdin.capi.Cipher; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 
import javax.crypto.*; 
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Симметричный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////////
public final class CipherSpi extends javax.crypto.CipherSpi implements Closeable
{
	// провайдер, слот и имя алгоритма
	private final Provider provider; private final int slot; private String name; 
    
    // параметры алгоритма и генератор случайных данных
    private AlgorithmParametersSpi parameters; private SecureRandom random; 
    
    // режим шифрования, дополнения и синхропосылка
    private String mode; private PaddingMode padding; private int opmode; 
    
    // алгоритм шифрования, ключ и синхропосылка
	private IAlgorithm algorithm; private Object key; 
	
	// конструктор
	public CipherSpi(Provider provider, String name) 
	{ 
		// сохранить параметры
		this.provider = provider; this.slot = provider.addObject(this); this.name = name; 
        
        // инициализировать переменные
        parameters = new AlgorithmParametersSpi(provider, name); random = null; 

		// инициализировать параметры
        mode = "NONE"; padding = PaddingMode.NONE; opmode = 0; algorithm = null; key = null;
	}  
    // освободить выделенные ресурсы
    @Override public void close() throws IOException
    { 
        // освободить выделенные ресурсы
        if (key instanceof IRefObject) RefObject.release((IRefObject)key);
        
        // освободить выделенные ресурсы
        RefObject.release(algorithm); provider.removeObject(slot); 
    }
	@Override protected final void engineSetMode(String mode) throws NoSuchAlgorithmException 
	{
        // обработать указание режима ECB и CBC
        if (mode.equalsIgnoreCase("NONE") || mode.equals("ECB") || mode.equals("CBC")) this.mode = mode;
        
        // обработать указание режима CBC с дополнением CTS
        else if (mode.equals("CTS")) { this.mode = "CBC"; padding = PaddingMode.CTS; } 
        
        // обработать указание режима CFB и OFB
        else if (mode.startsWith("CFB") || mode.startsWith("OFB") || mode.startsWith("CTR")) 
        { 
            // перейти на размер блока для режима
            this.mode = mode; mode = mode.substring(3); if (mode.length() != 0)
            {
                // прочитать размер блока для режима
                int modeBits = java.lang.Integer.parseInt(mode); 
            
                // проверить корректность размера блока
                if (modeBits == 0 || (modeBits % 8) != 0) throw new NoSuchAlgorithmException(); 
            }
        }
        // при ошибке выбросить исключение
        else throw new NoSuchAlgorithmException(); 
    }
	@Override protected final void engineSetPadding(String padding) throws NoSuchPaddingException 
	{
        // проверить указание дополнения 
        if (padding.equalsIgnoreCase("NoPadding")) return; 
        
        // обработать дополнения блочного алгоритма шифрования
        if (padding.equalsIgnoreCase("ZeroBytePadding" )) { this.padding = PaddingMode.ZERO;    return; }
        if (padding.equalsIgnoreCase("ISO7816-4Padding")) { this.padding = PaddingMode.ISO9797; return; }
        if (padding.equalsIgnoreCase("PKCS5Padding"    )) { this.padding = PaddingMode.PKCS5;   return; }
        if (padding.equalsIgnoreCase("ISO10126Padding" )) { this.padding = PaddingMode.PKCS5;   return; }
        if (padding.equalsIgnoreCase("CTSPadding"      )) { this.padding = PaddingMode.CTS;     return; }
        
        // обработать дополнения асимметричного шифрования
        if (padding.equalsIgnoreCase("PKCS1Padding") || padding.equalsIgnoreCase("OAEPPadding"))
        {
            // проверить отсутствие блочного шифрования 
            if (!mode.equalsIgnoreCase("NONE")) throw new NoSuchPaddingException(); 
            
            // указать полное имя алгоритма
            name = name + "/" + mode + "/" + padding; 
        }
        // дополнение не поддерживается 
        throw new javax.crypto.NoSuchPaddingException(); 
    }
	@Override
	protected final void engineInit(int opmode, 
        java.security.Key key, SecureRandom random) throws InvalidKeyException 
	{
		try { 
            // преобразовать тип параметров
            AlgorithmParametersSpi spi = provider.createParameters(name, null); 

            // инициализировать алгоритм
            engineInit(opmode, key, spi, random); 
        }
		// обработать возможное исключение
		catch (InvalidAlgorithmParameterException e) { throw new RuntimeException(e); }
		catch (InvalidParameterSpecException      e) { throw new RuntimeException(e); }
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		java.security.AlgorithmParameters parameters, SecureRandom random) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
        // преобразовать тип параметров
        AlgorithmParametersSpi spi = AlgorithmParametersSpi.getInstance(
            provider, name, parameters
        ); 
        // инициализировать алгоритм
        engineInit(opmode, key, spi, random); 
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		AlgorithmParameterSpec spec, SecureRandom random) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
    {
        try { 
            // преобразовать тип параметров
            AlgorithmParametersSpi spi = provider.createParameters(name, spec); 

            // инициализировать алгоритм
            engineInit(opmode, key, spi, random); 
        }
        // обработать возможное исключение
		catch (InvalidParameterSpecException e) 
        { 
            // изменить тип исключения 
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
    }
	protected final void engineInit(int opmode, java.security.Key key, 
		AlgorithmParametersSpi parameters, SecureRandom random) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		// сохранить переданные параметры
		this.opmode = opmode; this.parameters = parameters; this.random = random; 
        
        // получить закодированные параметры
        IEncodable encodable = parameters.getEncodable(); 
        
    	// создать блочный алгоритм симметричного шифрования
		try (IBlockCipher blockCipher = (IBlockCipher)provider.factory().createAlgorithm(
            parameters.getScope(), name, encodable, IBlockCipher.class))
        {
            // при наличии алгоритма
            if (blockCipher != null) 
            {
                // проверить тип ключа
                if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException(); 
                
                // преобразовать тип ключа
                try (ISecretKey secretKey = provider.translateSecretKey((javax.crypto.SecretKey)key)) 
                {
                    // создать режим шифрования 
                    try (Cipher cipher = createCipher(blockCipher))
                    {
                        // в зависимости от режима
                        if (opmode == javax.crypto.Cipher.ENCRYPT_MODE) 
                        {
                            // создать преобразование шифрования 
                            algorithm = createTransform(cipher, opmode, secretKey); 
                        }
                        // в зависимости от режима
                        else if (opmode == javax.crypto.Cipher.DECRYPT_MODE) 
                        {
                            // создать преобразование шифрования 
                            algorithm = createTransform(cipher, opmode, secretKey); 
                        }
                        else {
                            // создать алгоритм шифрования ключа
                            algorithm = cipher.createKeyWrap(padding); 

                            // сохранить ключ шифрования
                            this.key = RefObject.addRef(secretKey); 
                        }
                        return; 
                    }
                }
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
        
        // создать алгоритм симметричного шифрования
		try (Cipher cipher = (Cipher)provider.factory().createAlgorithm(
            parameters.getScope(), name, encodable, Cipher.class))
        {
            // при наличии алгоритма
            if (cipher != null) { if (!mode.equalsIgnoreCase("NONE")) throw new InvalidAlgorithmParameterException(); 
            
                // проверить тип ключа
                if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException(); 
             
                // преобразовать тип ключа
                try (ISecretKey secretKey = provider.translateSecretKey((javax.crypto.SecretKey)key)) 
                {
                    // в зависимости от режима
                    if (opmode == javax.crypto.Cipher.ENCRYPT_MODE) 
                    {
                        // создать преобразование шифрования 
                        algorithm = createTransform(cipher, opmode, secretKey); 
                    }
                    // в зависимости от режима
                    else if (opmode == javax.crypto.Cipher.DECRYPT_MODE) 
                    {
                        // создать преобразование шифрования 
                        algorithm = createTransform(cipher, opmode, secretKey); 
                    }
                    else {
                        // создать алгоритм шифрования ключа
                        algorithm = cipher.createKeyWrap(padding); 

                        // сохранить ключ шифрования
                        this.key = RefObject.addRef(secretKey); 
                    }
                    return; 
                }
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
        
        // для алгоритмов шифрования ключа
        if (opmode == javax.crypto.Cipher.WRAP_MODE || opmode == javax.crypto.Cipher.UNWRAP_MODE)
        {
			// создать алгоритм шифрования ключа
			try (IAlgorithm keyWrap = provider.factory().createAlgorithm(
                parameters.getScope(), name, encodable, KeyWrap.class))
            {
                // при наличии алгоритма
                if (keyWrap != null) { if (!mode.equalsIgnoreCase("NONE")) throw new InvalidAlgorithmParameterException(); 
                
                    // проверить тип ключа
                    if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException(); 

                    // преобразовать тип ключа
                    this.key = provider.translateSecretKey((javax.crypto.SecretKey)key); 

                    // сохранить используемый алгоритм
                    this.algorithm = RefObject.addRef(keyWrap); return;
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
        }
        // для алгоритмов зашифрования ключа
        if (opmode == javax.crypto.Cipher.WRAP_MODE)
        {    
            // создать алгоритм асимметричного шифрования
            try (IAlgorithm encipherment = provider.factory().createAlgorithm(
                parameters.getScope(), name, encodable, Encipherment.class))
            {
                // при наличии алгоритма
                if (encipherment != null) { if (!mode.equalsIgnoreCase("NONE")) throw new InvalidAlgorithmParameterException(); 
                    
                    // проверить тип ключа
                    if (!(key instanceof java.security.PublicKey)) throw new InvalidKeyException();
                    
                    // преобразовать тип ключа
                    this.key = provider.translatePublicKey((java.security.PublicKey)key);  
                    
                    // сохранить используемый алгоритм
                    this.algorithm = RefObject.addRef(encipherment); return;
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
        }
        // для алгоритмов расшифрования ключа
        if (opmode == javax.crypto.Cipher.UNWRAP_MODE)
        {
            // создать алгоритм асимметричного шифрования
            try (IAlgorithm decipherment = provider.factory().createAlgorithm(
                parameters.getScope(), name, encodable, Decipherment.class))
            {
                // при наличии алгоритма
                if (decipherment != null) { if (!mode.equalsIgnoreCase("NONE")) throw new InvalidAlgorithmParameterException(); 
                    
                    // проверить тип ключа
                    if (!(key instanceof java.security.PrivateKey)) throw new InvalidKeyException();
                    
                    // преобразовать тип ключа
                    this.key = provider.translatePrivateKey((java.security.PrivateKey)key);  
                    
                    // сохранить используемый алгоритм
                    this.algorithm = RefObject.addRef(decipherment); return;
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
        }
        // неподдерживаемый алгоритм
        throw new InvalidAlgorithmParameterException(); 
	}
	@Override
	protected final java.security.AlgorithmParameters engineGetParameters() 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmParameters(provider, parameters); 
    }
    // создать алгоритм шифрования
    private Cipher createCipher(IBlockCipher blockCipher) 
        throws InvalidAlgorithmParameterException, IOException
    {
        // указать режим по умолчанию и синхропосылку
        CipherMode mode = new CipherMode.ECB(); byte[] iv = engineGetIV();
                
        // определить размер блока 
        int blockSize = blockCipher.blockSize(); 
                
        // указать параметры режима
        if (this.mode.equals("CBC")) mode = new CipherMode.CBC(iv); 
        
        // в зависимости от режима
        else if (this.mode.startsWith("CFB")) 
        {
            // извлечь размер блока
            String str = this.mode.substring(3); if (str.length() != 0) 
            {
                // раскодировать размер блока
                blockSize = java.lang.Integer.parseInt(str) / 8; 
            }
            // указать параметры режима
            mode = new CipherMode.CFB(iv, blockSize); 
        } 
        // в зависимости от режима
        else if (this.mode.startsWith("OFB")) 
        {
            // извлечь размер блока
            String str = this.mode.substring(3); if (str.length() != 0) 
            {
                // раскодировать размер блока
                blockSize = java.lang.Integer.parseInt(str) / 8; 
            }
            // указать параметры режима
            mode = new CipherMode.OFB(iv, blockSize); 
        }
        // в зависимости от режима
        else if (this.mode.startsWith("CTR")) 
        {
            // извлечь размер блока
            String str = this.mode.substring(3); if (str.length() != 0) 
            {
                // раскодировать размер блока
                blockSize = java.lang.Integer.parseInt(str) / 8; 
            }
            // указать параметры режима
            mode = new CipherMode.CTR(iv, blockSize);  
        }
        // операция не поддерживается
        if (mode == null) throw new InvalidAlgorithmParameterException();
            
        // создать режим шифрования
        return blockCipher.createBlockMode(mode); 
    }
    // создать преобразование шифрования
    private Transform createTransform(Cipher cipher, int opmode, ISecretKey key) 
        throws InvalidKeyException, IOException
    {
        // в зависимости от режима
        if (opmode == javax.crypto.Cipher.ENCRYPT_MODE) 
        {
            // создать алгоритм зашифрования
            try (Transform transform = cipher.createEncryption(key, padding)) 
            {
                // инициализировать алгоритм
                transform.init(); return RefObject.addRef(transform); 
            }
        }
        // в зависимости от режима
        else if (opmode == javax.crypto.Cipher.DECRYPT_MODE) 
        {
            // создать алгоритм расшифрования
            try (Transform transform = cipher.createDecryption(key, padding)) 
            {
                // инициализировать алгоритм
                transform.init(); return RefObject.addRef(transform); 
            }
        }
        // при ошибке выбросить исключение
        else throw new IllegalStateException(); 
    }
	@Override
	protected final int engineGetKeySize(java.security.Key key) throws InvalidKeyException 
	{
        // проверить тип ключа
        if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException(); 
        
        // выполнить преобразование типа
        javax.crypto.SecretKey secretKey = (javax.crypto.SecretKey)key; 
        
		// преобразовать тип ключа
		try (ISecretKey nativeKey = provider.translateSecretKey(secretKey))
        {
            // вернуть размер ключа
            return nativeKey.length() * 8; 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }
	}
	@Override
	protected final int engineGetBlockSize() 
	{
        // проверить наличие инициализации
        if (algorithm == null) throw new IllegalStateException(); 
        
        // для алгоритма преобразования 
        if (algorithm instanceof Transform)
        {
            // вернуть размер блока
            return ((Transform)algorithm).blockSize(); 
        }
        return 0; 
	}
	@Override
	protected final int engineGetOutputSize(int inputLen) 
	{
        // определить размер блока
        int blockSize = engineGetBlockSize(); 
        
		// операция не поддерживается
		if (blockSize == 0) throw new UnsupportedOperationException();
        
		// вернуть требуемый размер буфера
		return inputLen + blockSize; 
	}
	@Override protected final byte[] engineGetIV() 
    { 
        try { 
            // получить синхропосылку
            return parameters.engineGetParameterSpec(IvParameterSpec.class).getIV(); 
        }
        // обработать возможное исключение
        catch (InvalidParameterSpecException e) { return null; }
    }
	@Override
	protected final int engineUpdate(byte[] input, int inputOffset, int inputLen, 
		byte[] output, int outputOffset) throws javax.crypto.ShortBufferException 
	{
		// зашифровать/расшифровать данные
		byte[] buffer = engineUpdate(input, inputOffset, inputLen);
		
		// проверить размер буфера
		if (output.length - outputOffset < buffer.length) 
        {
            // при ошибке выбросить исключение
            throw new javax.crypto.ShortBufferException(); 
        }
		// скопировать данные
		System.arraycopy(buffer, 0, output, 0, buffer.length); return buffer.length; 
	}
	@Override 
    protected final byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) 
	{
        // проверить наличие инициализации
        if (algorithm == null) throw new IllegalStateException(); 

        // проверить тип алгоритма
        if (algorithm instanceof Encipherment || algorithm instanceof Decipherment)
        {
            // при ошибке выбросить исключение
            throw new IllegalStateException(); 
        }
        // проверить тип алгоритма
        if (algorithm instanceof KeyWrap) throw new IllegalStateException(); 
        
		// выделить буфер требуемого размера
		byte[] buffer = new byte[engineGetOutputSize(inputLen)];
		try {
			// зашифровать/расшифровать данные
			int outputLen = ((Transform)algorithm).update(input, inputOffset, inputLen, buffer, 0); 

			// проверить размер буфера
			if (buffer.length == outputLen) return buffer; 

			// выделить буфер требуемого размера
			byte[] output = new byte[outputLen];

			// скопировать данные
			System.arraycopy(buffer, 0, output, 0, outputLen); return output; 
		}
		// обработать возможное исключение
		catch (Exception e) { throw new RuntimeException(e); }
	}
	@Override
	protected final int engineDoFinal(byte[] input, int inputOffset, int inputLen, 
		byte[] output, int outputOffset) throws javax.crypto.ShortBufferException 
	{
		// завершить зашифрование/расшифрование данных
		byte[] buffer = engineDoFinal(input, inputOffset, inputLen);
		
		// проверить размер буфера
		if (output.length - outputOffset < buffer.length)
        {
            // при ошибке выбросить исключение
            throw new javax.crypto.ShortBufferException(); 
        }
		// скопировать данные
		System.arraycopy(buffer, 0, output, 0, buffer.length); return buffer.length; 
	}
	@Override
	protected final byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
	{
        // проверить наличие инициализации
        if (algorithm == null) throw new IllegalStateException(); 
        
        // для алгоритмов шифрования 
        if (algorithm instanceof Transform)
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[engineGetOutputSize(inputLen)];
            try {
                // завершить зашифрование/расшифрование данных
                int outputLen = ((Transform)algorithm).finish(input, inputOffset, inputLen, buffer, 0); 

                // проверить размер буфера
                if (buffer.length == outputLen) return buffer; 

                // выделить буфер требуемого размера
                byte[] output = new byte[outputLen];

                // скопировать данные
                System.arraycopy(buffer, 0, output, 0, outputLen); return output;
            }
            // обработать возможное исключение
            catch (Exception e) { throw new RuntimeException(e); }
        }
        // для алгоритма шифрования ключа
        else if (algorithm instanceof KeyWrap)
        {
            // скопировать данные
            byte[] buffer = new byte[inputLen]; System.arraycopy(input, inputOffset, buffer, 0, inputLen);
            
            // указать тип алгоритма
            aladdin.capi.SecretKeyFactory keyFactory = aladdin.capi.SecretKeyFactory.GENERIC; 

            // проверить допустимость вызова
            if (opmode == javax.crypto.Cipher.ENCRYPT_MODE || opmode == javax.crypto.Cipher.WRAP_MODE) 
            {
                // преобразовать тип ключа
                try (ISecretKey CEK = keyFactory.create(buffer))
                {
                    // создать объект генератора случайных данных
                    try (IRand rand = provider.createRand(random))
                    {
                        // зашифровать ключ
                        return ((KeyWrap)algorithm).wrap(rand, (ISecretKey)key, CEK); 
                    }
                }
                // обработать возможное исключение
                catch (Exception e) { throw new RuntimeException(e); }  	
            }
            else {
                // расшифровать ключ
                try (ISecretKey unwrappedKey = ((KeyWrap)algorithm).unwrap(
                    (ISecretKey)key, buffer, keyFactory)) 
                {
                    // проверить тип ключа
                    if (unwrappedKey.value() == null) throw new InvalidKeyException(); 
                    
                    // вернуть значение ключа
                    return unwrappedKey.value(); 
                }
                // обработать возможное исключение
                catch (Exception e) { throw new RuntimeException(e); }
            }
        }
        // для алгоритма асимметричного зашифрования
        else if (algorithm instanceof Encipherment)
        {
            // скопировать данные
            byte[] buffer = new byte[inputLen]; System.arraycopy(input, inputOffset, buffer, 0, inputLen);
        
            // создать объект генератора случайных данных
            try (IRand rand = provider.createRand(random))
            {
                // зашифровать данные
                return ((Encipherment)algorithm).encrypt((IPublicKey)key, rand, buffer); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }
        }
        else {
            // скопировать данные
            byte[] buffer = new byte[inputLen]; System.arraycopy(input, inputOffset, buffer, 0, inputLen);
        
			// расшифровать данные
			try { return ((Decipherment)algorithm).decrypt((IPrivateKey)key, buffer); }
            
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }
        }
	}
	@Override
	protected final byte[] engineWrap(java.security.Key key) throws InvalidKeyException 
	{
        // проверить допустимость вызова
        if (opmode != javax.crypto.Cipher.WRAP_MODE) throw new IllegalStateException(); 
        
        // проверить наличие инициализации
        if (algorithm == null) throw new IllegalStateException(); 
        
        // проверить тип ключа
        if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException();
        
        // выполнить преобразование типа
        javax.crypto.SecretKey secretKey = (javax.crypto.SecretKey)key; 
        
        // создать объект генератора случайных данных
        try (IRand rand = provider.createRand(random))
        {
            // для алгоритмов шифрования ключа
            if (algorithm instanceof KeyWrap)
            {
                // преобразовать тип ключа
                try (ISecretKey CEK = provider.translateSecretKey(secretKey))
                {
                    // зашифровать ключ
                    return ((KeyWrap)algorithm).wrap(rand, (ISecretKey)this.key, CEK); 
                }
            }
            // получить значение ключа
            else { byte[] value = secretKey.getEncoded(); 
                
                // проверить доступность значения ключа
                if (value == null) throw new InvalidKeyException();

                // зашифровать данные
                return ((Encipherment)algorithm).encrypt((IPublicKey)this.key, rand, value); 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }  	
    }
	@Override
	protected final java.security.Key engineUnwrap(byte[] wrappedKey, 
		String wrappedKeyAlgorithm, int wrappedKeyType) 
		throws InvalidKeyException, NoSuchAlgorithmException 
	{
        // проверить допустимость вызова
        if (opmode != javax.crypto.Cipher.UNWRAP_MODE) throw new IllegalStateException(); 
        
		// проверить тип ключа
		if (wrappedKeyType != javax.crypto.Cipher.SECRET_KEY) throw new NoSuchAlgorithmException();
        
        // получить фабрику кодирования 
        aladdin.capi.SecretKeyFactory keyFactory = provider.getSecretKeyFactory(wrappedKeyAlgorithm); 
        
        // проверить наличие фабрики
        if (keyFactory == null) throw new NoSuchAlgorithmException(); 

        // для алгоритмов шифрования ключа
        if (algorithm instanceof KeyWrap)
        {
            // расшифровать ключ
            try (ISecretKey nativeKey = ((KeyWrap)algorithm).unwrap((ISecretKey)key, wrappedKey, keyFactory))
            {
                // зарегистрировать симметричный ключ
                return new SecretKey(provider, wrappedKeyAlgorithm, nativeKey); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }  	
        }
        else {
            try { 
                // расшифровать данные
                byte[] value = ((Decipherment)algorithm).decrypt((IPrivateKey)key, wrappedKey); 

                // создать объект ключа
                try (ISecretKey nativeKey = keyFactory.create(value))
                {
                    // зарегистрировать симметричный ключ
                    return new SecretKey(provider, wrappedKeyAlgorithm, nativeKey); 
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }
        }
	}
}
