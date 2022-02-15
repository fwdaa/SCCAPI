package aladdin.capi.stb.sign.stb11762;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.capi.stb.stb11762.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Алгоритм выработки подписи СТБ 1176.2 на основе хэш-значения СТБ 1176.1
///////////////////////////////////////////////////////////////////////
public class SignDataPro extends aladdin.capi.SignData
{
    // алгоритм выработки подписи и алгоритм хэширования
    private final aladdin.capi.SignHash signAlgorithm; private Hash hashAlgorithm;
    
    // конструктор
    public SignDataPro(aladdin.capi.SignHash signAlgorithm) 
    { 
        // сохранить переданные параметры
        this.signAlgorithm = RefObject.addRef(signAlgorithm); hashAlgorithm = null;
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    { 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); 
        
        // освободить выделенные ресурсы
        RefObject.release(signAlgorithm); super.onClose();         
    } 
	// инициализировать алгоритм
	@Override public void init(IPrivateKey privateKey, IRand rand) throws IOException 
	{ 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null; 
        
        // выполнить преобразование типа
        IBDSParameters parameters = (IBDSParameters)privateKey.parameters(); 
        
        // создать алгоритм хэширования
        hashAlgorithm = createHashAlgorithm(privateKey, parameters.bdsH()); 
        
        // проверить наличие алгоритма хэширования
        if (hashAlgorithm == null) throw new UnsupportedOperationException(); 

		// инициализировать алгоритм хэширования
		super.init(privateKey, rand); hashAlgorithm.init(); 
	}
	// обработать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException 
	{
		// прохэшировать данные
		hashAlgorithm.update(data, dataOff, dataLen); 
	}
	// получить подпись данных
	@Override public byte[] finish(IRand rand) throws IOException
    {
		// получить хэш-значение
		byte[] hash = new byte[hashAlgorithm.hashSize()]; hashAlgorithm.finish(hash, 0);  
        
        // подписать хэш-значение
        byte[] signature = signAlgorithm.sign(privateKey(), rand, null, hash); 
            
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null; 

        // вернуть вычисленную подпись
        super.finish(rand); return signature; 
    }
    // создать алгоритм хэширования
    protected Hash createHashAlgorithm(IPrivateKey privateKey, byte[] start) throws IOException
    { 
        // создать алгоритм хэширования
        return new aladdin.capi.stb.hash.STB11761(start);     
    }
}
