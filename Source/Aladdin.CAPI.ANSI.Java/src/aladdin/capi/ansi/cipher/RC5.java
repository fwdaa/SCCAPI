package aladdin.capi.ansi.cipher;
import aladdin.asn1.*;
import aladdin.asn1.ansi.*;
import aladdin.asn1.ansi.rsa.*;
import aladdin.capi.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC5
///////////////////////////////////////////////////////////////////////////
public final class RC5 extends BlockCipher
{
    // размер блока, число раундов и базовая реализация
    private final int blockSize; private final int rounds; 

    // конструктор
    public RC5(Factory factory, SecurityStore scope, int blockSize, int rounds) throws IOException
    {
        // сохранить переданные параметры	
        super(factory, scope); this.blockSize = blockSize; this.rounds = rounds; 
    } 
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return new aladdin.capi.ansi.keys.RC5(KeySizes.range(1, 256)); 
    } 
    // размер блока
    @Override public final int blockSize() { return blockSize; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // в зависимости от режима
        if (mode instanceof CipherMode.CBC) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new RC5CBCParameter(
                new aladdin.asn1.Integer(16), new aladdin.asn1.Integer(rounds), 
                new aladdin.asn1.Integer(blockSize * 8), 
                new OctetString(((CipherMode.CBC)mode).iv())
            ); 
            // получить алгоритм шифрования
            try (Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), OID.RSA_RC5_CBC, parameters, Cipher.class))
            {
                // изменить режим дополнения
                if (cipher != null) return new BlockMode.PaddingConverter(cipher, PaddingMode.ANY); 
            }
        }
        // вызвать базовую функцию
        return createBlockMode(mode, 0); 
    }
}
