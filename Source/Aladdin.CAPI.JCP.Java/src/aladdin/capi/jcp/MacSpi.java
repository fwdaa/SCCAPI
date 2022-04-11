package aladdin.capi.jcp;
import aladdin.*;
import aladdin.capi.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки
///////////////////////////////////////////////////////////////////////////////
public final class MacSpi extends javax.crypto.MacSpi implements Closeable 
{
    // используемый провайдер и номер слота
	private final Provider provider; private final int slot;
    // имя алгоритма, алгоритм вычисления имитовставки и ключ
    private final String name; private Mac macAlgorithm; private ISecretKey key;  
	
	// конструктор
	public MacSpi(Provider provider, String name) 
	{ 
        // сохранить переданные параметры
        this.provider = provider; this.slot = provider.addObject(this); 
        
        // инициализировать переменные
        this.name = name; macAlgorithm = null; key = null; 
	} 
    // освободить выделенные ресурсы
    @Override public void close() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(macAlgorithm); 
        
        // освободить выделенные ресурсы
        RefObject.release(key); provider.removeObject(slot); 
    }
    
    // инициализировать алгоритм
	@Override protected void engineInit(java.security.Key key, AlgorithmParameterSpec paramSpec) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
    {
        // проверить тип ключа
        if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException();
        
        // выполнить преобразование типа
        javax.crypto.SecretKey secretKey = (javax.crypto.SecretKey)key; 
		try {
			// раскодировать параметры
			AlgorithmParametersSpi parameters = provider.createParameters(name, paramSpec); 
            
            // создать алгоритм вычисления имитовставки
            try (Mac macAlgorithm = (Mac)provider.factory().createAlgorithm(
                parameters.getScope(), name, parameters.getEncodable(), Mac.class))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) throw new InvalidAlgorithmParameterException(); 
                    
                // преобразовать тип ключа
                try (ISecretKey nativeKey = provider.translateSecretKey(secretKey))
                {
                    // инициализировать алгоритм
                    macAlgorithm.init(nativeKey); this.key = RefObject.addRef(nativeKey);
                    
                    // сохранить созданный алгоритм
                    this.macAlgorithm = RefObject.addRef(macAlgorithm);
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }  
		}
        // обработать возможное исключение
		catch (InvalidParameterSpecException e) 
        { 
            // при ошибке выбросить исключение
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
	}
    // определить размер имитовставки
	@Override protected int engineGetMacLength() 
	{
        // проверить наличие алгоритма
        if (macAlgorithm == null) throw new IllegalStateException(); 
        
		// вернуть размер имитовставки
		return macAlgorithm.macSize(); 
	}
    // переустановить алгоритм 
	@Override protected void engineReset() 
	{ 
        // проверить наличие алгоритма
        if (macAlgorithm == null) throw new IllegalStateException(); 
        
		// инициализировать алгоритм
		try { macAlgorithm.init(key); }
        
        // обработать возможное исключение
        catch (Exception e) { throw new RuntimeException(e); }
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
        if (macAlgorithm == null) throw new IllegalStateException(); 
        
		// захэшировать данные
		try { macAlgorithm.update(input, offset, len); }
        
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
	@Override
	protected byte[] engineDoFinal() 
	{
        // проверить наличие алгоритма
        if (macAlgorithm == null) throw new IllegalStateException(); 
        
		// выделить буфер для имитовставки
		byte[] digest = new byte[macAlgorithm.macSize()];
		try { 
    		// получить имитовставку
        	macAlgorithm.finish(digest, 0); 
            
            // переустановить алгоритм
            macAlgorithm.init(key); return digest; 
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
        
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
}
