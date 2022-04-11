package aladdin.capi.jcp;
import aladdin.*;
import aladdin.capi.*; 
import java.security.*; 
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
public final class MessageDigestSpi extends java.security.MessageDigestSpi implements Closeable
{
    // используемый провайдер и номер слота 
	private final Provider provider; private final int slot; 
    // имя алгоритма и алгоритм хэширования
    private final String name; private Hash hashAlgorithm; 
	
	// конструктор
	public MessageDigestSpi(Provider provider, String name) 
	{ 
        // сохранить переданные параметры
        this.provider = provider; this.slot = provider.addObject(this); 
        
        // сохранить переданные параметры
        this.name = name; hashAlgorithm = null; 
	} 
    // освободить выделенные ресурсы
    @Override public void close() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); provider.removeObject(slot); 
    }
    // инициализировать алгоритм
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidAlgorithmParameterException 
	{
        try {
            // создать параметры алгоритма
            AlgorithmParametersSpi parameters = provider.createParameters(name, paramSpec); 
            
            // создать алгоритм хэширования
            try (Hash hashAlgorithm = (Hash)provider.factory().createAlgorithm(
                parameters.getScope(), name, parameters.getEncodable(), Hash.class))
            {
                // проверить наличие алгоритма
                if (hashAlgorithm == null) throw new InvalidAlgorithmParameterException(); 
                
                // инициализировать алгоритм
                hashAlgorithm.init(); this.hashAlgorithm = RefObject.addRef(hashAlgorithm);
            }
        }
        // обработать возможную ошибку
        catch (InvalidParameterSpecException e) 
        { 
            // при ошибке выбросить исключение
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
    }
    // определить размер хэш-значения
	@Override protected final int engineGetDigestLength() 
    { 
        // проверить наличие алгоритма
        if (hashAlgorithm == null) throw new IllegalStateException(); 
        
        // определить размер хэш-значения
        return hashAlgorithm.hashSize(); 
    } 
    // переустановить алгоритм 
	@Override protected final void engineReset() 
    { 
        // проверить наличие алгоритма
        if (hashAlgorithm == null) throw new IllegalStateException(); 
        
        // инициализировать алгоритм
        try { hashAlgorithm.init(); }
        
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
    } 
    // захэшировать данные
	@Override protected final void engineUpdate(byte input) 
	{ 
		// захэшировать байт
		engineUpdate(new byte[] {input}, 0, 1); 
	} 
    // захэшировать данные
	@Override protected final void engineUpdate(byte[] input, int offset, int len) 
	{
        // проверить наличие алгоритма
        if (hashAlgorithm == null) throw new IllegalStateException(); 
        
		// захэшировать данные
		try { hashAlgorithm.update(input, offset, len); }

        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
    }
    // получить хэш-значение
	@Override protected final byte[] engineDigest() 
	{
        // проверить наличие алгоритма
        if (hashAlgorithm == null) throw new IllegalStateException(); 
        
		// выделить буфер для хэш-значения
		byte[] digest = new byte[hashAlgorithm.hashSize()];
		try { 
    		// получить хэш-значение
    		hashAlgorithm.finish(digest, 0); hashAlgorithm.init(); return digest;  
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
}
