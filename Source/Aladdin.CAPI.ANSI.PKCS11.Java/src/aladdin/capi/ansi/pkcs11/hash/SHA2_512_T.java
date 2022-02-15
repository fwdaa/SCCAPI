package aladdin.capi.ansi.pkcs11.hash;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования SHA2-512
///////////////////////////////////////////////////////////////////////////////
public class SHA2_512_T extends aladdin.capi.pkcs11.Hash
{
    // конструктор
    public SHA2_512_T(Applet applet, int bits) 
     
        // сохранить переданные параметры
        { super(applet); this.bits = bits; } private final int bits;
    
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
		// выделить память для параметров
		return new Mechanism(API.CKM_SHA512_T, bits); 
	}
	// размер хэш-значения в байтах
	@Override public int hashSize() { return (bits + 7) / 8; } 
	// размер блока в байтах
	@Override public int blockSize() { return 128; }
    
	// завершить хэширование данных
	@Override public int finish(byte[] buf, int bufOff) throws IOException
    {
        // проверить наличие данных
        if (total() != 0) return super.finish(buf, bufOff); 

        // создать алгоритм хэширования
        try (aladdin.capi.Hash algorithm = new aladdin.capi.ansi.hash.SHA2_512_T(bits))
        {
            // вычислить хэш-значение
            byte[] hash = algorithm.hashData(new byte[0], 0, 0); 

            // скопировать хэш-значение
            System.arraycopy(hash, 0, buf, bufOff, hash.length); return hash.length; 
        }
    }
}
