package aladdin.capi.gost.wrap;
import aladdin.capi.gost.cipher.*;
import aladdin.*;
import aladdin.capi.*; 
import java.io.*;
import java.security.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа KExp15
///////////////////////////////////////////////////////////////////////////
public class KExp15 extends KeyWrap
{
    // алгоритм шифрования и алгоритм вычисления имитовставки
    private final Cipher cipher; private final Mac macAlgorithm; private final byte[] iv; 
    
    // создать алгоритм шифрования ключа
    public static KExp15 create(Factory factory, 
        SecurityStore scope, int blockSize, byte[] iv) throws IOException
    {
        // создать режим шифрования CTR
        try (Cipher cipher = GOSTR3412.createCTR(factory, scope, blockSize, iv))
        {
            // проверить наличие алгоритма
            if (cipher == null) return null; 
            
            // создать имитовставку OMAC
            try (Mac macAlgorithm = GOSTR3412.createOMAC(factory, scope, blockSize))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) return null; 
            
                // вернуть алгоритм шифрования ключа
                return new KExp15(cipher, macAlgorithm, iv); 
            }
        }
    }
    // конструктор
    public KExp15(Cipher cipher, Mac macAlgorithm, byte[] iv)
    {
        // проверить корректность размера
        if (iv.length != cipher.blockSize() / 2) throw new IllegalArgumentException(); 
        
        // сохранить переданные параметры
        this.cipher = RefObject.addRef(cipher); this.iv = iv; 

        // сохранить переданные параметры
        this.macAlgorithm = RefObject.addRef(macAlgorithm); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException    
    { 
        // освободить выделенные ресурсы
        RefObject.release(macAlgorithm); 

        // освободить выделенные ресурсы
        RefObject.release(cipher); super.onClose();         
    } 
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return new SecretKeyFactory(new int[] { 64 }); 
    } 
	// зашифровать ключ
	@Override public byte[] wrap(IRand rand, ISecretKey key, ISecretKey CEK) 
        throws IOException, InvalidKeyException
    {
        // проверить наличие значения ключа
        byte[] keyValue = key.value(); if (keyValue == null) throw new InvalidKeyException(); 
                
        // выделить память для значений ключей
        byte[] key1 = new byte[keyValue.length / 2]; byte[] key2 = new byte[keyValue.length / 2];

        // скопировать значения ключей
        System.arraycopy(keyValue,           0, key1, 0, key1.length);
        System.arraycopy(keyValue, key1.length, key2, 0, key2.length);
        
        // проверить наличие значения 
        byte[] value = CEK.value(); if (value == null) throw new InvalidKeyException(); 
        
        // выделить буфер для вычисления имитовставки
        byte[] iv_key = new byte[iv.length + value.length]; 
        
        // скопировать синхропосылку и значение ключа
        System.arraycopy(iv   , 0, iv_key,         0,    iv.length);
        System.arraycopy(value, 0, iv_key, iv.length, value.length);
        
        // создать ключ для вычисления имитовставки
        try (ISecretKey macKey = macAlgorithm.keyFactory().create(key1))
        {
            // вычислить имитовставку
            byte[] mac = macAlgorithm.macData(macKey, iv_key, 0, iv_key.length); 

            // выделить буфер для вычисления имитовставки
            byte[] key_mac = new byte[value.length + mac.length]; 
        
            // скопировать значение ключа и имитовставку
            System.arraycopy(value, 0, key_mac,            0, value.length);
            System.arraycopy(mac  , 0, key_mac, value.length,   mac.length);
            
            // создать ключ для шифрования
            try (ISecretKey cipherKey = cipher.keyFactory().create(key2))
            {
                // зашифровать данные
                return cipher.encrypt(cipherKey, PaddingMode.NONE, key_mac, 0, key_mac.length); 
            }
        }
    }
	// расшифровать ключ
	@Override public ISecretKey unwrap(ISecretKey key, byte[] wrappedCEK, 
        SecretKeyFactory keyFactory) throws IOException, InvalidKeyException
    {
        // проверить наличие значения ключа
        byte[] keyValue = key.value(); if (keyValue == null) throw new InvalidKeyException(); 
                
        // выделить память для значений ключей
        byte[] key1 = new byte[keyValue.length / 2]; byte[] key2 = new byte[keyValue.length / 2];

        // скопировать значения ключей
        System.arraycopy(keyValue,           0, key1, 0, key1.length);
        System.arraycopy(keyValue, key1.length, key2, 0, key2.length);
        
        // создать ключ для шифрования
        try (ISecretKey cipherKey = cipher.keyFactory().create(key2))
        {
            // расшифровать данные
            byte[] key_mac = cipher.decrypt(cipherKey, 
                PaddingMode.NONE, wrappedCEK, 0, wrappedCEK.length
            ); 
            // выделить буфер для имитовставки
            byte[] check = new byte[macAlgorithm.macSize()]; 
            
            // проверить размер данных
            if (key_mac.length < check.length) throw new IOException(); 
            
            // выделить память для значения ключа
            byte[] value = new byte[key_mac.length - check.length]; 
            
            // извлечь значение ключа и имитовставку
            System.arraycopy(key_mac,            0, value, 0, value.length);
            System.arraycopy(key_mac, value.length, check, 0, check.length);
            
            // выделить буфер для вычисления имитовставки
            byte[] iv_key = new byte[iv.length + value.length]; 
            
            // скопировать синхропосылку и значение ключа
            System.arraycopy(   iv, 0, iv_key,         0,    iv.length);
            System.arraycopy(value, 0, iv_key, iv.length, value.length);
            
            // создать ключ для вычисления имитовставки
            try (ISecretKey macKey = macAlgorithm.keyFactory().create(key1))
            {
                // вычислить имитовставку
                byte[] mac = macAlgorithm.macData(macKey, iv_key, 0, iv_key.length); 
                
                // проверить совпадение имитовставок
                if (!Arrays.equals(mac, check)) throw new IOException(); 
            }
            // вернуть значение ключа
            return keyFactory.create(value); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Factory factory, SecurityStore scope, int blockSize) throws Exception
    {
        byte[] KEK = new byte[] {
            (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, 
            (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F, 
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
            (byte)0x18, (byte)0x19, (byte)0x1A, (byte)0x1B, 
            (byte)0x1C, (byte)0x1D, (byte)0x1E, (byte)0x1F, 
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23, 
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27, 
            (byte)0x28, (byte)0x29, (byte)0x2A, (byte)0x2B, 
            (byte)0x2C, (byte)0x2D, (byte)0x2E, (byte)0x2F, 
            (byte)0x38, (byte)0x39, (byte)0x3A, (byte)0x3B, 
            (byte)0x3C, (byte)0x3D, (byte)0x3E, (byte)0x3F, 
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, 
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37            
        };
        byte[] CEK = new byte[] {
            (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
            (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, 
            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
            (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
            (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, 
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10, 
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
            (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF 
        };
        if (blockSize == 8)
        {
            byte[] iv = new byte[] { 
                (byte)0x67, (byte)0xBE, (byte)0xD6, (byte)0x54 
            }; 
            // вывести сообщение
            Test.dump("IV", iv);
            
            try (KeyWrap keyWrap = create(factory, scope, 
                8, new byte[] { (byte)0x67, (byte)0xBE, (byte)0xD6, (byte)0x54 }
            )){
                knownTest(null, keyWrap, KEK, CEK, new byte[] {
                    (byte)0xCF, (byte)0xD5, (byte)0xA1, (byte)0x2D, 
                    (byte)0x5B, (byte)0x81, (byte)0xB6, (byte)0xE1, 
                    (byte)0xE9, (byte)0x9C, (byte)0x91, (byte)0x6D, 
                    (byte)0x07, (byte)0x90, (byte)0x0C, (byte)0x6A, 
                    (byte)0xC1, (byte)0x27, (byte)0x03, (byte)0xFB, 
                    (byte)0x3A, (byte)0xBD, (byte)0xED, (byte)0x55, 
                    (byte)0x56, (byte)0x7B, (byte)0xF3, (byte)0x74, 
                    (byte)0x2C, (byte)0x89, (byte)0x9C, (byte)0x75, 
                    (byte)0x5D, (byte)0xAF, (byte)0xE7, (byte)0xB4, 
                    (byte)0x2E, (byte)0x3A, (byte)0x8B, (byte)0xD9, 
                }); 
            }
        }
        if (blockSize == 16)
        {
            byte[] iv = new byte[] { 
                (byte)0x09, (byte)0x09, (byte)0x47, (byte)0x2D, 
                (byte)0xD9, (byte)0xF2, (byte)0x6B, (byte)0xE8, 
            }; 
            // вывести сообщение
            Test.dump("IV", iv);
            
            try (KeyWrap keyWrap = create(factory, scope, 
                16, new byte[] { 
                    (byte)0x09, (byte)0x09, (byte)0x47, (byte)0x2D, 
                    (byte)0xD9, (byte)0xF2, (byte)0x6B, (byte)0xE8, 
                }
            )){
                knownTest(null, keyWrap, KEK, CEK, new byte[] {
                    (byte)0xE3, (byte)0x61, (byte)0x84, (byte)0xE8, 
                    (byte)0x4E, (byte)0x8D, (byte)0x73, (byte)0x6F, 
                    (byte)0xF3, (byte)0x6C, (byte)0xC2, (byte)0xE5, 
                    (byte)0xAE, (byte)0x06, (byte)0x5D, (byte)0xC6, 
                    (byte)0x56, (byte)0xB2, (byte)0x3C, (byte)0x20, 
                    (byte)0xF5, (byte)0x49, (byte)0xB0, (byte)0x2F, 
                    (byte)0xDF, (byte)0xF8, (byte)0x8E, (byte)0x1F, 
                    (byte)0x3F, (byte)0x30, (byte)0xD8, (byte)0xC2, 
                    (byte)0x9A, (byte)0x53, (byte)0xF3, (byte)0xCA, 
                    (byte)0x55, (byte)0x4D, (byte)0xBA, (byte)0xD8, 
                    (byte)0x0D, (byte)0xE1, (byte)0x52, (byte)0xB9, 
                    (byte)0xA4, (byte)0x62, (byte)0x5B, (byte)0x32, 
                }); 
            }
        }
    }
}
