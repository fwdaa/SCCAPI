package aladdin.capi.ansi.pkcs11.hash;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования SHA3-384
///////////////////////////////////////////////////////////////////////////////
public class SHA3_384 extends aladdin.capi.pkcs11.Hash
{
	// конструктор
	public SHA3_384(Applet applet) { super(applet); }
	
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
		// выделить память для параметров
		return new Mechanism(API.CKM_SHA3_384); 
	}
	// размер хэш-значения в байтах
	@Override public int hashSize() { return 48; } 
	// размер блока в байтах
	@Override public int blockSize() { return 104; }
    
	// завершить хэширование данных
	@Override public int finish(byte[] buf, int bufOff) throws IOException
    {
        // проверить наличие данных
        if (total() != 0) return super.finish(buf, bufOff); 

        // создать алгоритм хэширования
        try (aladdin.capi.Hash algorithm = new aladdin.capi.ansi.hash.SHA3(384))
        {
            // вычислить хэш-значение
            byte[] hash = algorithm.hashData(new byte[0], 0, 0); 

            // скопировать хэш-значение
            System.arraycopy(hash, 0, buf, bufOff, hash.length); return hash.length; 
        }
    }
}
