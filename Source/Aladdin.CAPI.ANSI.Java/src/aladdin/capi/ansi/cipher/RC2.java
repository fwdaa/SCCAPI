package aladdin.capi.ansi.cipher;
import aladdin.*;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.ansi.*;
import aladdin.asn1.ansi.rsa.*;
import aladdin.capi.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC2
///////////////////////////////////////////////////////////////////////////
public final class RC2 extends RefObject implements IBlockCipher
{
    // фабрика алгоритмов и область видимости
    private final Factory factory; private final SecurityStore scope; 
    // эффективное число битов и размер ключа
    private final int effectiveKeyBits; private final int keyLength; 
        
    // конструктор
    public RC2(Factory factory, SecurityStore scope, int effectiveKeyBits, int keyLength) 
    {
        // сохранить переданные параметры	
        this.factory = RefObject.addRef(factory); this.scope = RefObject.addRef(scope);

        // сохранить переданные параметры
        this.effectiveKeyBits = effectiveKeyBits; this.keyLength = keyLength; 
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
        return aladdin.capi.ansi.keys.RC2.INSTANCE; 
    } 
    // размер ключей 
    @Override public final int[] keySizes () { return new int[] {keyLength}; } 
    // размер блока
    @Override public final int blockSize() { return 8; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // закодировать эффективное число битов
        aladdin.asn1.Integer version = RC2ParameterVersion.getVersion(effectiveKeyBits); 
            
        // в зависимости от режима
        if (mode instanceof CipherMode.ECB) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.RSA_RC2_ECB), version
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 

            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.RSA_RC2_CBC), new RC2CBCParams(
                    version, new OctetString(((CipherMode.CBC)mode).iv())
                )
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 

            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        // режим не поддерживается
        throw new UnsupportedOperationException();
    }
}
