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
	private final Provider provider; private final int slot; private final String[] names; 
    
    // параметры алгоритма и генератор случайных данных
    private AlgorithmParametersSpi parameters; private SecureRandom random; 
    
    // алгоритм шифрования, ключ и синхропосылка
	private IAlgorithm algorithm; private Object key; private int opmode; 
	
	// конструктор
	public CipherSpi(Provider provider, String name) 
	{ 
		// сохранить параметры
		this.provider = provider; this.slot = provider.addObject(this); 
        
        // инициализировать переменные
        this.names = new String[] { name, null }; parameters = null; 

		// инициализировать параметры
        random = null; algorithm = null; key = null; opmode = 0; 
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
        // преобразовать имя в верхний регистр
        mode = mode.toUpperCase(); if (mode.equals("NONE")) return; 
        
        // обработать указание режима ECB и CBC
        if (mode.equals("ECB") || mode.equals("CBC")) names[0] += "/" + mode; 
            
        // обработать указание режима CBC с дополнением CTS
        else if (mode.equals("CTS")) { names[0] += "/CBC"; names[1] = "CTSPadding"; } 
        
        // обработать указание режима CFB и OFB
        else if (mode.startsWith("CFB") || mode.startsWith("OFB") || mode.startsWith("CTR")) 
        { 
            // сохранить режим
            names[0] += "/" + mode; if (mode.length() != 3) 
            { 
                // прочитать размер блока для режима
                int modeBits = java.lang.Integer.parseInt(mode.substring(3)); 
            
                // проверить корректность размера блока
                if (modeBits == 0 || (modeBits % 8) != 0) throw new NoSuchAlgorithmException(); 
            }
        }
        // при ошибке выбросить исключение
        else throw new NoSuchAlgorithmException(); 
    }
	@Override protected final void engineSetPadding(String padding) throws NoSuchPaddingException 
	{
        // при наличии дополнения CTS
        if (names[1] != null && names[1].equals("CTSPadding"))
        {
            // проверить корректность данных
            if (padding.equalsIgnoreCase("NoPadding" )) return; 
            if (padding.equalsIgnoreCase("CTSPadding")) return; 

            // дополнение не поддерживается 
            throw new javax.crypto.NoSuchPaddingException(); 
        }
        // обработать отсутствие дополнения 
        if (padding.equalsIgnoreCase("NoPadding")) { names[1] = padding; return; }
        
        // обработать дополнения блочного алгоритма шифрования
        if (padding.equalsIgnoreCase("ZeroBytePadding" )) { names[1] = padding; return; }
        if (padding.equalsIgnoreCase("PKCS5Padding"    )) { names[1] = padding; return; }
        if (padding.equalsIgnoreCase("ISO10126Padding" )) { names[1] = padding; return; }
        if (padding.equalsIgnoreCase("ISO7816-4Padding")) { names[1] = padding; return; }
        if (padding.equalsIgnoreCase("CTSPadding"      )) { names[1] = padding; return; }
        
        // обработать дополнения асимметричного шифрования
        if (padding.equalsIgnoreCase("PKCS1Padding") || padding.equalsIgnoreCase("OAEPPadding"))
        {
            // проверить корректность режима
            if (names[0].contains("/")) throw new NoSuchPaddingException(); 
                
            // сохранить режим дополнения 
            names[0] += "/" + padding; return; 
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
            AlgorithmParametersSpi spi = provider.createParameters(names[0], null); 

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
            provider, names[0], parameters
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
            AlgorithmParametersSpi spi = provider.createParameters(names[0], spec); 

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
        try { 
            // создать блочный алгоритм симметричного шифрования
            Cipher cipher = provider.factory().createBlockMode(
                parameters.getScope(), names[0], encodable, engineGetIV()
            ); 
            // при наличии алгоритма
            if (cipher == null) cipher = (Cipher)provider.factory().createAlgorithm(
                parameters.getScope(), names[0], encodable, Cipher.class
            ); 
            // получить режим дополнения
            if (cipher != null) { try { PaddingMode padding = BlockPadding.parse(names[1]); 
             
                // проверить тип ключа
                if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException(); 

                // преобразовать тип ключа
                try (ISecretKey secretKey = provider.translateSecretKey((javax.crypto.SecretKey)key)) 
                {
                    // в зависимости от режима
                    if (opmode == javax.crypto.Cipher.ENCRYPT_MODE) 
                    {
                        // создать алгоритм зашифрования
                        try (Transform transform = cipher.createEncryption(secretKey, padding)) 
                        {
                            // инициализировать алгоритм
                            transform.init(); algorithm = RefObject.addRef(transform); return; 
                        }
                    }
                    // в зависимости от режима
                    else if (opmode == javax.crypto.Cipher.DECRYPT_MODE) 
                    {
                        // создать алгоритм расшифрования
                        try (Transform transform = cipher.createDecryption(secretKey, padding)) 
                        {
                            // инициализировать алгоритм
                            transform.init(); algorithm = RefObject.addRef(transform); return; 
                        }
                    }
                    else {
                        // создать алгоритм шифрования ключа
                        algorithm = cipher.createKeyWrap(padding); 

                        // сохранить ключ шифрования
                        this.key = RefObject.addRef(secretKey); 
                    }
                }
            }
            finally { cipher.close(); }}
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
        
        // проверить корректность имени
        if (names[1] != null) throw new InvalidAlgorithmParameterException();
        
        // для алгоритмов шифрования ключа
        if (opmode == javax.crypto.Cipher.WRAP_MODE || opmode == javax.crypto.Cipher.UNWRAP_MODE)
        {
			// создать алгоритм шифрования ключа
			try (IAlgorithm keyWrap = provider.factory().createAlgorithm(
                parameters.getScope(), names[0], encodable, KeyWrap.class))
            {
                // при наличии алгоритма
                if (keyWrap != null) 
                { 
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
                parameters.getScope(), names[0], encodable, Encipherment.class))
            {
                // при наличии алгоритма
                if (encipherment != null) 
                { 
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
                parameters.getScope(), names[0], encodable, Decipherment.class))
            {
                // при наличии алгоритма
                if (decipherment != null) 
                { 
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
