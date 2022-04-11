package aladdin.capi.jcp;
import aladdin.*;
import aladdin.capi.*; 
import aladdin.capi.Cipher; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Симметричный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////////
public final class CipherSpi extends javax.crypto.CipherSpi implements Closeable
{
	// провайдер, слот и идентификатор алгоритма
	private final Provider provider; private final int slot; private byte[] iv; 
    // параметры алгоритма и генератор случайных данных
    private AlgorithmParametersSpi parameters; private SecureRandom random; 

    // имя алгоритма, режим шифрования и дополнения 
    private final String name; private int mode; private PaddingMode padding; 
    // алгоритм шифрования, ключ и преобразование шифрования
	private IAlgorithm algorithm; private Object key; private Transform transform; 
	
	// конструктор
	public CipherSpi(Provider provider, String name) 
	{ 
		// сохранить параметры
		this.provider = provider; this.slot = provider.addObject(this); 
        
        // инициализировать переменные
        parameters = new AlgorithmParametersSpi(provider, name); random = null; 

		// инициализировать параметры
        this.name = name; mode = 0; padding = PaddingMode.NONE; 
        
		// инициализировать параметры
		algorithm = null; key = null; transform = null;
	}  
    // освободить выделенные ресурсы
    @Override public void close() throws IOException
    { 
        // освободить выделенные ресурсы
        if (key instanceof IRefObject) RefObject.release((IRefObject)key);
        
        // освободить выделенные ресурсы
        RefObject.release(transform); RefObject.release(algorithm); provider.removeObject(slot); 
    }
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		SecureRandom random) throws InvalidKeyException 
	{
		// инициализировать алгоритм
		try { engineInit(opmode, key, (AlgorithmParameterSpec)null, random); }
		
		// обработать возможное исключение
		catch (InvalidAlgorithmParameterException e) { throw new RuntimeException(e); }
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		java.security.AlgorithmParameters parameters, SecureRandom random) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		try { 
			// получить закодированное представление
			AlgorithmParameterSpec spec = (parameters != null) ? 
                parameters.getParameterSpec(KeyStoreParameterSpec.class) : null;
			
			// инициализировать алгоритм
			engineInit(opmode, key, spec, random); 
		}
		// обработать возможное исключение
		catch (InvalidParameterSpecException e) 
        { 
            // преобразовать тип исключения
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		AlgorithmParameterSpec spec, SecureRandom random) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		// сохранить переданные параметры
		this.random = random; this.mode = opmode; 
        
        // при наличии области видимости 
        SecurityStore scope = null; if (spec instanceof KeyStoreParameterSpec) 
        {
            // указать область видимости
            scope = ((KeyStoreParameterSpec)spec).getScope(); 
        }
        // при указании синхропосылки
        if (spec instanceof javax.crypto.spec.IvParameterSpec)
        {
            // извлчеь синхропосылку
            iv = ((javax.crypto.spec.IvParameterSpec)spec).getIV(); spec = null; 
        }
    	// преобразовать тип параметров
		try { parameters = provider.createParameters(name, spec); }
			
        // обработать возможное исключение
		catch (InvalidParameterSpecException e) 
        { 
            // изменить тип исключения 
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
    	// создать блочный алгоритм симметричного шифрования
		try (IAlgorithm cipher = provider.factory().createBlockCipher(
            scope, name, parameters.getEncodable()))
        {
            if (cipher != null) 
            { 
                // проверить тип ключа
                if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException(); 
        
                // преобразовать тип ключа
                this.key = provider.translateSecretKey((javax.crypto.SecretKey)key); 
                
                // сохранить используемый алгоритм
                this.algorithm = RefObject.addRef(cipher); return; 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e); }
        
        // создать алгоритм симметричного шифрования
		try (IAlgorithm cipher = provider.factory().createAlgorithm(
            scope, name, parameters.getEncodable(), Cipher.class))
        {
            if (cipher != null) 
            { 
                // проверить тип ключа
                if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException(); 
        
                // преобразовать тип ключа
                this.key = provider.translateSecretKey((javax.crypto.SecretKey)key); 
                
                // сохранить используемый алгоритм
                this.algorithm = RefObject.addRef(cipher); return;
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e); }
        
        // для алгоритмов зашифрования
        if (opmode == javax.crypto.Cipher.WRAP_MODE)
        {
			// создать алгоритм шифрования ключа
			try (IAlgorithm keyWrap = provider.factory().createAlgorithm(
                scope, name, parameters.getEncodable(), KeyWrap.class))
            {
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
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e); }
            
            // создать алгоритм асимметричного шифрования
            try (IAlgorithm encipherment = provider.factory().createAlgorithm(
                parameters.getScope(), name, parameters.getEncodable(), Encipherment.class))
            {
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
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e); }
        }
        // для алгоритмов зашифрования
        if (opmode == javax.crypto.Cipher.UNWRAP_MODE)
        {
			// создать алгоритм шифрования ключа
			try (IAlgorithm keyWrap = provider.factory().createAlgorithm(
                scope, name, parameters.getEncodable(), KeyWrap.class))
            {
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
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e); }
            
            // создать алгоритм асимметричного шифрования
            try (IAlgorithm decipherment = provider.factory().createAlgorithm(
                parameters.getScope(), name, parameters.getEncodable(), Decipherment.class))
            {
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
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e); }
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
	protected final void engineSetMode(String string) throws NoSuchAlgorithmException 
	{
        // проверить тип алгоритма
        if (!(algorithm instanceof IBlockCipher)) throw new IllegalStateException(); 
        
        // выполнить преобразование типа
        IBlockCipher blockCipher = (IBlockCipher)algorithm; CipherMode mode = null; 
        try {  
            // указать параметры режима
            if (string.equals("ECB")) mode = new CipherMode.ECB(); 
            else {
                // определить размер блока и синхропосылку
                int blockSize = blockCipher.blockSize(); byte[] iv = engineGetIV();
                
                // указать параметры режима
                if (string.equals("CBC")) mode = new CipherMode.CBC(iv, blockSize); else 
                if (string.equals("CFB")) mode = new CipherMode.CFB(iv, blockSize); else 
                if (string.equals("OFB")) mode = new CipherMode.OFB(iv, blockSize); else 
                if (string.equals("CTR")) mode = new CipherMode.CTR(iv, blockSize);  
            }
            // операция не поддерживается
            if (mode == null) throw new UnsupportedOperationException();
            
            // создать режим шифрования
            try (Cipher cipher = blockCipher.createBlockMode(mode))
            {
                // переназначить алгоритм
                algorithm.release(); algorithm = RefObject.addRef(cipher);
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new UnsupportedOperationException(e); }
	}
	@Override
	protected final void engineSetPadding(String string) 
        throws javax.crypto.NoSuchPaddingException 
	{
        // проверить тип алгоритма
        if (algorithm instanceof Encipherment || algorithm instanceof Decipherment)
        {
            // при ошибке выбросить исключение
            throw new IllegalStateException(); 
        }
        // проверить тип алгоритма
        if (algorithm instanceof KeyWrap) throw new IllegalStateException(); 
        
        // указать режим дополнения
        if (string.equals("NoPadding"   )) padding = PaddingMode.NONE ; else 
        if (string.equals("PKCS5Padding")) padding = PaddingMode.PKCS5; else 
        if (string.equals("ZeroPadding" )) padding = PaddingMode.ZERO ; else 
        if (string.equals("ISOPadding"  )) padding = PaddingMode.ISO  ; else 
        if (string.equals("CTSPadding"  )) padding = PaddingMode.CTS  ; else 
        
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
    // перейти в алгоритм шифрования
    private Cipher gotoCipher() throws IOException
    {
        // проверить тип алгоритма
        if (algorithm instanceof Cipher) return (Cipher)algorithm;
        
        // проверить тип алгоритма
        if (!(algorithm instanceof IBlockCipher)) throw new IllegalStateException(); 
        
        // выполнить преобразование типа
        IBlockCipher blockCipher = (IBlockCipher)algorithm; 
        
        // создать режим шифрования
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.ECB()))
        {
            // переназначить алгоритм
            algorithm.release(); algorithm = RefObject.addRef(cipher); 
        }
        return (Cipher)algorithm; 
    }
    // создать преобразование шифрования
    private Transform createTransform() throws IOException, InvalidKeyException
    {
        // перейти в алгоритм шифрования
        Cipher cipher = gotoCipher();
        
        // в зависимости от режима
        if (mode == javax.crypto.Cipher.ENCRYPT_MODE) 
        {
            // создать алгоритм зашифрования
            try (Transform transform = cipher.createEncryption((ISecretKey)key, padding)) 
            {
                // инициализировать алгоритм
                transform.init(); return RefObject.addRef(transform); 
            }
        }
        // в зависимости от режима
        else if (mode == javax.crypto.Cipher.DECRYPT_MODE) 
        {
            // создать алгоритм расшифрования
            try (Transform transform = cipher.createDecryption((ISecretKey)key, padding)) 
            {
                // инициализировать алгоритм
                transform.init(); return RefObject.addRef(transform); 
            }
        }
        // при ошибке выбросить исключение
        throw new IllegalStateException(); 
    }
    // создать алгоритм шифрования ключа
    private KeyWrap createKeyWrap() throws IOException
    {
        // проверить тип алгоритма
        if (algorithm instanceof KeyWrap) 
        {
            // вернуть алгоритм шифрования ключа
            return RefObject.addRef((KeyWrap)algorithm); 
        }
        // создать алгоритм шифрования ключа
        return gotoCipher().createKeyWrap(padding);  
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
        
        // для блочного алгоритма шифрования
        if (algorithm instanceof IBlockCipher)
        {
            // вернуть размер блока
            return ((IBlockCipher)algorithm).blockSize(); 
        }
        // для симметричного алгоритма шифрования
        if (algorithm instanceof Cipher)
        {
            // вернуть размер блока
            return ((Cipher)algorithm).blockSize(); 
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
        // определить размер блока
        if (iv != null) return iv; int blockSize = engineGetBlockSize();

		// вернуть нулевую синхропосылку
		return (blockSize != 0) ? new byte[blockSize] : null; 
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
            // создать преобразование шифрования 
            if (transform == null) transform = createTransform(); 
        
			// зашифровать/расшифровать данные
			int outputLen = transform.update(input, inputOffset, inputLen, buffer, 0); 

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
	protected final byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
	{
        // проверить наличие инициализации
        if (algorithm == null) throw new IllegalStateException(); 
        
        // для алгоритмов шифрования 
        if (algorithm instanceof IBlockCipher || algorithm instanceof Cipher)
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[engineGetOutputSize(inputLen)];
            try {
                // создать преобразование шифрования 
                if (transform == null) transform = createTransform(); 

                // завершить зашифрование/расшифрование данных
                int outputLen = transform.finish(input, inputOffset, inputLen, buffer, 0); 

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
            SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 

            // проверить допустимость вызова
            if (mode == javax.crypto.Cipher.ENCRYPT_MODE || mode == javax.crypto.Cipher.WRAP_MODE) 
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
	protected final byte[] engineWrap(java.security.Key key) throws InvalidKeyException 
	{
        // проверить допустимость вызова
        if (mode != javax.crypto.Cipher.WRAP_MODE) throw new IllegalStateException(); 
        
        // проверить наличие инициализации
        if (algorithm == null) throw new IllegalStateException(); 
        
        // проверить тип ключа
        if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException();
        
        // выполнить преобразование типа
        javax.crypto.SecretKey secretKey = (javax.crypto.SecretKey)key; 
        
        // создать объект генератора случайных данных
        try (IRand rand = provider.createRand(random))
        {
            // для алгоритмов шифрования 
            if (algorithm instanceof IBlockCipher || algorithm instanceof Cipher || algorithm instanceof KeyWrap)
            {
                // создать алгоритм шифрования ключа
                try (KeyWrap keyWrap = createKeyWrap()) 
                {
                    // преобразовать тип ключа
                    try (ISecretKey CEK = provider.translateSecretKey(secretKey))
                    {
                        // зашифровать ключ
                        return keyWrap.wrap(rand, (ISecretKey)this.key, CEK); 
                    }
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
        if (mode != javax.crypto.Cipher.UNWRAP_MODE) throw new IllegalStateException(); 
        
		// проверить тип ключа
		if (wrappedKeyType != javax.crypto.Cipher.SECRET_KEY) throw new NoSuchAlgorithmException();
        
        // указать тип алгоритма
        SecretKeyFactory keyFactory = provider.factory().getSecretKeyFactory(wrappedKeyAlgorithm); 

        // для алгоритмов шифрования 
        if (algorithm instanceof IBlockCipher || algorithm instanceof Cipher || algorithm instanceof KeyWrap)
        {
            // создать алгоритм шифрования ключа
            try (KeyWrap keyWrap = createKeyWrap()) 
            { 
                // расшифровать ключ
                try (ISecretKey nativeKey = keyWrap.unwrap((ISecretKey)key, wrappedKey, keyFactory))
                {
                    // зарегистрировать симметричный ключ
                    return new SecretKey(provider, wrappedKeyAlgorithm, nativeKey); 
                }
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
