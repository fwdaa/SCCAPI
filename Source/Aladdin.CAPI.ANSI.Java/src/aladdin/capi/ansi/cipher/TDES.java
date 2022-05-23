package aladdin.capi.ansi.cipher;
import aladdin.asn1.*;
import aladdin.asn1.ansi.*;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования TDES
///////////////////////////////////////////////////////////////////////////
public final class TDES extends BlockCipher
{
    // конструктор
    public TDES(Factory factory, SecurityStore scope) { super(factory, scope); }
    
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return new aladdin.capi.ansi.keys.TDES(new int[] {16, 24}); 
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
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), OID.SSIG_TDES_ECB, parameters, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        // вызвать базовую функцию
        return createBlockMode(mode, 0); 
    }
}
