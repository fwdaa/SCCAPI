package aladdin.capi.ansi.cipher;
import aladdin.asn1.*;
import aladdin.asn1.ansi.*;
import aladdin.asn1.ansi.rsa.*;
import aladdin.capi.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC2
///////////////////////////////////////////////////////////////////////////
public final class RC2 extends BlockCipher
{
    // эффективное число битов
    private final int effectiveKeyBits; 
        
    // конструктор
    public RC2(Factory factory, SecurityStore scope, int effectiveKeyBits) 
    {
        // сохранить переданные параметры	
        super(factory, scope); this.effectiveKeyBits = effectiveKeyBits; 
    } 
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return new aladdin.capi.ansi.keys.RC2(KeySizes.range(1, 128)); 
    } 
    // размер блока
    @Override public final int blockSize() { return 8; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // закодировать эффективное число битов
        aladdin.asn1.Integer version = 
            RC2ParameterVersion.getVersion(effectiveKeyBits); 
            
        // в зависимости от режима
        if (mode instanceof CipherMode.ECB) 
        {
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), OID.RSA_RC2_ECB, version, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new RC2CBCParams(
                version, new OctetString(((CipherMode.CBC)mode).iv())
            ); 
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), OID.RSA_RC2_CBC, parameters, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        // вызвать базовую функцию
        return createBlockMode(mode, 0); 
    }
}
