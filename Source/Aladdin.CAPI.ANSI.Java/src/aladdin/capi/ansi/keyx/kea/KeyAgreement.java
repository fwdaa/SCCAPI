package aladdin.capi.ansi.keyx.kea;
import aladdin.*; 
import aladdin.math.*;
import aladdin.capi.*;
import java.security.*;
import java.math.*;
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа
///////////////////////////////////////////////////////////////////////////
public class KeyAgreement extends RefObject implements IKeyAgreement
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
        
    // значение дополнения
    private static final byte[] PAD = new byte[] {
        (byte)0x72, (byte)0xF1, (byte)0xA8, (byte)0x7E, (byte)0x92,
        (byte)0x82, (byte)0x41, (byte)0x98, (byte)0xAB, (byte)0x0B
    };
    // алгоритм шифрования блока
    private final Cipher skipjack; 
        
    // конструктор
    public KeyAgreement(Cipher skipjack) 
    { 
        // сохранить переданные параметры
        this.skipjack = RefObject.addRef(skipjack); 
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException 
    {
        // освободить используемые ресурсы
        RefObject.release(skipjack); super.onClose();            
    }
    // наследовать ключ на стороне оправителе
    @Override public DeriveData deriveKey(aladdin.capi.IPrivateKey privateKey, 
        aladdin.capi.IPublicKey publicKey, 
        IRand rand, SecretKeyFactory keyFactory, int keySize) throws IOException
    {
        // преобразовать тип параметров
        aladdin.capi.ansi.kea.IParameters dhParameters = 
            (aladdin.capi.ansi.kea.IParameters)publicKey.parameters(); 

        // личный ключ
        aladdin.capi.ansi.kea.IPrivateKey dhPrivateKey = 
            (aladdin.capi.ansi.kea.IPrivateKey)privateKey; 

        // открытый ключ
        aladdin.capi.ansi.kea.IPublicKey dhPublicKey = 
            (aladdin.capi.ansi.kea.IPublicKey)publicKey; 
            
        // извлечь параметры
        BigInteger p = dhParameters.getP(); BigInteger g = dhParameters.getG();
        BigInteger q = dhParameters.getQ(); 
            
        // извлечь значения ключей
        BigInteger x = dhPrivateKey.getX(); BigInteger y = dhPublicKey.getY(); 
        
        // указать начальные условия
        BigInteger r = BigInteger.ZERO; BigInteger w = BigInteger.ZERO;
        
        // указать генератор случайных чисел
        try (aladdin.capi.Random random = new aladdin.capi.Random(rand)) 
        {
            // определить требуемый размер в битах
            for (int bitsQ = q.bitLength(); w.signum() == 0; )
            { 
                // сгенерировать случайное число
                do { r = new BigInteger(bitsQ, random); }

                // проверить условие генерации
                while (r.signum() == 0 || r.compareTo(p) >= 0);

                // выполнить сложение степеней 
                w = y.modPow(r, p).add(y.modPow(x, p)).mod(p); 
            }
        }
        // выполнить возведение в степень
        BigInteger R = g.modPow(r, p); 
        
        // получить закодированное представление числа
        byte[] encodedR = Convert.fromBigInteger(R, ENDIAN, 128); 
            
        // создать ключ
        try (ISecretKey key = createKey(w, keyFactory)) 
        { 
            // вернуть значение ключа и нонки
            return new DeriveData(key, encodedR); 
        }
    }
    // наследовать ключ на стороне получателе
    @Override public ISecretKey deriveKey(aladdin.capi.IPrivateKey privateKey, 
        aladdin.capi.IPublicKey publicKey, 
        byte[] random, SecretKeyFactory keyFactory, int keySize) throws IOException
    {
        // преобразовать тип параметров
        aladdin.capi.ansi.kea.IParameters dhParameters = 
            (aladdin.capi.ansi.kea.IParameters)publicKey.parameters(); 

        // личный ключ
        aladdin.capi.ansi.kea.IPrivateKey dhPrivateKey = 
            (aladdin.capi.ansi.kea.IPrivateKey)privateKey; 

        // открытый ключ
        aladdin.capi.ansi.kea.IPublicKey dhPublicKey = 
            (aladdin.capi.ansi.kea.IPublicKey)publicKey; 

        // извлечь параметры
        BigInteger p = dhParameters.getP(); BigInteger q = dhParameters.getQ();
            
        // извлечь значения ключей
        BigInteger x = dhPrivateKey.getX(); BigInteger y = dhPublicKey.getY(); 
            
        //  раскодировать случайное значение
        BigInteger R = Convert.toBigInteger(random, ENDIAN); 
            
        // проверить корректность значения
        if (R.signum() == 0 || R.compareTo(p) >= 0) throw new IOException(); 
            
        // проверить корректность значения
        if (!R.modPow(q, p).equals(BigInteger.ONE)) throw new IOException();

        // выполнить сложение степеней 
        BigInteger w = R.modPow(x, p).add(y.modPow(x, p)).mod(p); 
            
        // проверить корректность данных и создать ключ
        if (w.signum() == 0) throw new IOException(); return createKey(w, keyFactory);
    }
    private ISecretKey createKey(BigInteger w, SecretKeyFactory keyFactory) throws IOException
    {
        // получить закодированное представление числа
        byte[] encodedW = Convert.fromBigInteger(w, ENDIAN, 128); 

        // создать два ключа
        byte[] v1 = Arrays.copyOfRange(encodedW,  0, 10); 
        byte[] v2 = Arrays.copyOfRange(encodedW, 10, 20); 
            
        // выполнить сложение с дополнением
        for (int i = 0; i < 10; i++) v1[i] ^= PAD[i]; 
        
        // создать ключ шифрования
        try (ISecretKey key = skipjack.keyFactory().create(v1))
        {
            // создать алгоритм шифрования блока
            try (Transform transform = skipjack.createEncryption(key, PaddingMode.NONE)) 
            {
                // зашифровать блок
                transform.init(); transform.update(v2, 0, 8, v2, 0); 
                
                v2[8] ^= v2[0]; v2[9] ^= v2[1];

                // зашифровать блок
                transform.update(v2, 0, 8, v2, 0); return keyFactory.create(v2); 
            }
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
    }
}
