package aladdin.capi.jcp;
import aladdin.RefObject;
import aladdin.capi.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи
///////////////////////////////////////////////////////////////////////////////
public final class SignatureSpi extends java.security.SignatureSpi implements Closeable
{
    // используемый провайдер и номер слота
	private final Provider provider; private final int slot;
    
	// параметры алгоритма и используемый генератор случайных данных
	private AlgorithmParametersSpi parameters; private SecureRandom random; 
    
    // открытый ключ и буфер приема входных данных
    private IPublicKey publicKey; private final ByteArrayOutputStream stream; 

	// конструктор
	public SignatureSpi(Provider provider, int slot, AlgorithmParametersSpi parameters) 
	{ 
        // сохранить переданные параметры
        this.provider = provider; this.slot = slot; stream = new ByteArrayOutputStream();
        
        // инициализировать переменные
        this.parameters = parameters; this.random = null;
    } 
    // освободить выделенные ресурсы
    @Override public void close() throws IOException
    { 
        // освободить выделенные ресурсы
        provider.clearObject(slot); stream.close(); 
    }
	@Deprecated
	@Override
	protected final void engineSetParameter(String param, java.lang.Object value) 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Deprecated
	@Override
	protected final java.lang.Object engineGetParameter(String param) 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final void engineSetParameter(AlgorithmParameterSpec paramSpec) 
		throws InvalidAlgorithmParameterException 
	{
		// раскодировать параметры
		try { parameters = AlgorithmParametersSpi.create(provider, paramSpec); } 
			
        // обработать возможную ошибку
		catch (InvalidParameterSpecException e) 
        { 
            // при ошибке выбросить исключение
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
	}
	@Override
	protected final AlgorithmParameters engineGetParameters() 
    { 
        // проверить наличие параметров
        if (parameters == null) return null; 
        
        // вернуть параметры алгоритма
        return new AlgorithmParameters(provider, parameters); 
    }
	@Override
	protected final void engineInitSign(
        java.security.PrivateKey key) throws InvalidKeyException 
	{
        // инициализировать алгоритм
        engineInitSign(key, null); 
	}
	@Override
	protected final void engineInitSign(
        java.security.PrivateKey key, SecureRandom random) 
            throws InvalidKeyException 
	{
        // проверить наличие параметров
        if (parameters == null) throw new IllegalStateException(); 
        
        // сохранить генератор случайных данных
        this.random = random; this.publicKey = null; 
        
        // указать фабрику ключей
        KeyFactorySpi keyFactory = new KeyFactorySpi(provider); 
        
        // преобразовать тип ключа
        try (IPrivateKey privateKey = keyFactory.translatePrivateKey(key))
        { 
            // создать алгоритм выработки подписи
            try (SignData signAlgorithm = (SignData)privateKey.factory().createAlgorithm(
                privateKey.scope(), parameters.getEncodable(), SignData.class)) 
            {
                // проверить наличие алгоритма
                if (signAlgorithm == null) throw new InvalidKeyException(); 
                
                // инициализировать алгоритм 
                if (random == null) signAlgorithm.init(privateKey, provider.getRand());
                    
                // указать генератор случайных данных
                else try (IRand rand = new Rand(random, null))
                {
                    // инициализировать алгоритм 
                    signAlgorithm.init(privateKey, rand); 
                }
                // сохранить алгоритм
                provider.setObject(slot, RefObject.addRef(signAlgorithm));
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }  	
	}
	@Override
	protected final void engineInitVerify(
        java.security.PublicKey key) throws InvalidKeyException 
	{
        // проверить наличие параметров
        if (parameters == null) throw new IllegalStateException(); 
        
        // указать фабрику ключей
        KeyFactorySpi keyFactory = new KeyFactorySpi(provider); 
        
        // преобразовать тип ключа
        publicKey = keyFactory.translatePublicKey(key); stream.reset();
         
        // создать алгоритм проверки подписи
        try (VerifyData verifyAlgorithm = (VerifyData)provider.getFactory().createAlgorithm(
            parameters.getScope(), parameters.getEncodable(), VerifyData.class)) 
        {
            // проверить наличие алгоритма
            if (verifyAlgorithm == null) throw new InvalidKeyException(); 
            
            // сохранить алгоритм
            provider.setObject(slot, RefObject.addRef(verifyAlgorithm));
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }  	
	}
	@Override
	protected final void engineUpdate(byte input) throws SignatureException
	{ 
		// захэшировать байт
		engineUpdate(new byte[] {input}, 0, 1); 
	} 
	@Override
	protected final void engineUpdate(byte[] input, int offset, int len) 
		throws SignatureException
	{
		// записать данные в буфер
        if (publicKey != null) stream.write(input, offset, len); 
        else {
            // получить алгоритм
            SignData signAlgorithm = (SignData)provider.getObject(slot); 
        
            // проверить наличие алгоритма
            if (signAlgorithm == null) throw new IllegalStateException(); 
            
			// обработать данные
            try { signAlgorithm.update(input, offset, len); }
            
    		// обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }  	
        }
	}
	@Override
	protected final byte[] engineSign() throws SignatureException 
	{
        // проверить допустимость вызова
        if (publicKey != null) throw new IllegalStateException(); 
        
        // получить алгоритм
        SignData signAlgorithm = (SignData)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (signAlgorithm == null) throw new IllegalStateException(); 
        try { 
            // получить подпись данных
            if (random == null) return signAlgorithm.finish(provider.getRand());
            
            // указать генератор случайных данных
            try (IRand rand = new Rand(random, null))
            {
                // получить подпись данных
                return signAlgorithm.finish(rand);
            }
        }
		// обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }  	
	}
	@Override
	protected final int engineSign(byte[] output, int offset, int length) 
		throws SignatureException 
	{
		// получить подпись данных
		byte[] signature = engineSign(); 
		
		// проверить размер подписи
		if (length < signature.length) throw new SignatureException();
		
		// скопировать подпись
		System.arraycopy(signature, 0, output, offset, signature.length);
		
		// вернуть размер подписи
		return signature.length; 
	}
	@Override
	protected final boolean engineVerify(byte[] signature, int offset, int length) 
		throws SignatureException 
	{
		// выделить буфер для подписи
		byte[] buffer = new byte[length];
		
		// скопировать подпись в буфер
		System.arraycopy(signature, 0, buffer, 0, length);
		
		// проверить подпись
		return engineVerify(signature); 
	}
	@Override
	protected final boolean engineVerify(byte[] signature) throws SignatureException 
	{
        // проверить допустимость вызова
        if (publicKey == null) throw new IllegalStateException(); 

        // получить алгоритм
        VerifyData verifyAlgorithm = (VerifyData)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (verifyAlgorithm == null) throw new IllegalStateException(); 
        try { 
    		// получить закэшированные данные 
    		byte[] data = stream.toByteArray(); 
		
			// проверить подпись данных 
			verifyAlgorithm.verify(publicKey, data, 0, data.length, signature); 
            
            return true; 
		}
		// обработать возможное исключение
		catch (IOException e) { return false; }
	}
}
