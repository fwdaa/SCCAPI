package aladdin.capi.stb.sign.stb11762;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.capi.stb.stb11762.*;
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи СТБ 1176.2 на основе хэш-значения СТБ 1176.1
///////////////////////////////////////////////////////////////////////
public class VerifyDataPro extends aladdin.capi.VerifyData
{
    // алгоритм проверки подписи
    private final aladdin.capi.VerifyHash verifyAlgorithm; 
    // алгоритм хэширования 
    private Hash hashAlgorithm; 
    
    // конструктор
    public VerifyDataPro(aladdin.capi.VerifyHash verifyAlgorithm) 
    { 
        // сохранить переданные параметры
        this.verifyAlgorithm = RefObject.addRef(verifyAlgorithm); hashAlgorithm = null;
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    {
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); 
        
        // освободить выделенные ресурсы
        RefObject.release(verifyAlgorithm); super.onClose();
    }
	// инициализировать алгоритм
	@Override public void init(IPublicKey publicKey, byte[] signature) 
        throws SignatureException, IOException
	{ 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null; 
        
        // выполнить преобразование типа
        IBDSParameters parameters = (IBDSParameters)publicKey.parameters(); 
        
        // создать алгоритм хэширования
        hashAlgorithm = createHashAlgorithm(publicKey, parameters.bdsH()); 
            
        // проверить наличие алгоритма хэширования
        if (hashAlgorithm == null) throw new UnsupportedOperationException();
        
		// инициализировать алгоритм хэширования
		super.init(publicKey, signature); hashAlgorithm.init(); 
	}
	// обработать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException
	{
		// прохэшировать данные
		hashAlgorithm.update(data, dataOff, dataLen); 
	}
	// получить подпись данных
	@Override public void finish() throws IOException, SignatureException
	{
		// получить хэш-значение
		byte[] hash = new byte[hashAlgorithm.hashSize()]; hashAlgorithm.finish(hash, 0); 
        
		// проверить подпись хэш-значения
		try { verifyAlgorithm.verify(publicKey(), null, hash, signature()); }
            
        // освободить выделенные ресурсы
        finally { RefObject.release(hashAlgorithm); hashAlgorithm = null; }
	}
    // создать алгоритм хэширования
    protected Hash createHashAlgorithm(IPublicKey publicKey, byte[] start) throws IOException 
    { 
        // создать алгоритм хэширования
        return new aladdin.capi.stb.hash.STB11761(start); 
    }
}
