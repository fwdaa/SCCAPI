package aladdin.capi.ansi.cipher;
import aladdin.asn1.*;
import aladdin.asn1.ansi.*;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования DES-X
///////////////////////////////////////////////////////////////////////////
public final class DESX extends BlockCipher
{
    // конструктор
    public DESX(Factory factory, SecurityStore scope) { super(factory, scope); }
    
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.ansi.keys.DESX.INSTANCE; 
    } 
    // размер блока
    @Override public final int blockSize() { return 8; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // в зависимости от режима
        if (mode instanceof CipherMode.ECB) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = Null.INSTANCE; 
            
            // получить алгоритм шифрования
            try (Cipher engine = (Cipher)factory().createAlgorithm(
                scope(), OID.SSIG_DES_ECB, parameters, Cipher.class)) 
            {
                // вернуть алгоритм шифрования
                if (engine == null) throw new UnsupportedOperationException();
                
                // создать модификацию алгоритма
                try (Cipher desX = new aladdin.capi.ansi.engine.DESX(engine))
                {
                    // вернуть режим алгоритма
                    return new BlockMode.PaddingConverter(desX, PaddingMode.ANY); 
                }
            }
        }
        // в зависимости от режима
        if (mode instanceof CipherMode.CBC) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new OctetString(((CipherMode.CBC)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), OID.RSA_DESX_CBC, parameters, Cipher.class
            ); 
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
        }
        // вызвать базовую функцию
        return createBlockMode(mode, 24); 
	}
}
