package aladdin.capi.ansi.cipher;
import aladdin.*;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.ansi.*;
import aladdin.asn1.ansi.rsa.*;
import aladdin.capi.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC5
///////////////////////////////////////////////////////////////////////////
public final class RC5 extends RefObject implements IBlockCipher
{
    // фабрика алгоритмов и область видимости
    private final Factory factory; private final SecurityStore scope; 
    // размер блока и число раундов
    private final int blockSize; private final int rounds; 

    // конструктор
    public RC5(Factory factory, SecurityStore scope, 
        int blockSize, int rounds) throws IOException
    {
        // сохранить переданные параметры	
        this.factory = RefObject.addRef(factory); this.scope = RefObject.addRef(scope);

        // сохранить переданные параметры	
        this.blockSize = blockSize; this.rounds = rounds; 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(scope); RefObject.release(factory); super.onClose();
    }
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.ansi.keys.RC5.INSTANCE; 
    } 
    // размер ключей
    @Override public final int[] keySizes () { return KeySizes.range(1, 256); } 
    // размер блока
    @Override public final int blockSize() { return blockSize; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // в зависимости от режима
        if (mode instanceof CipherMode.CBC) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.RSA_RC5_CBC), new RC5CBCParameter(
                    new aladdin.asn1.Integer(16), new aladdin.asn1.Integer(rounds), 
                    new aladdin.asn1.Integer(blockSize * 8), 
                    new OctetString(((CipherMode.CBC)mode).iv())
                )
            );
            // получить алгоритм шифрования
            try (Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, parameters, Cipher.class))
            {
                // изменить режим дополнения
                if (cipher != null) return new BlockMode.ConvertPadding(cipher, PaddingMode.ANY); 
            }
        }
        // режим не поддерживается
        throw new UnsupportedOperationException();
    }
}
