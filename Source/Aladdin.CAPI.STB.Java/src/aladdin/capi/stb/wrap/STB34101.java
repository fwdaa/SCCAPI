package aladdin.capi.stb.wrap;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////////
public class STB34101 extends KeyWrap
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // алгоритм шифрования блока 
    private final Cipher belt; private final byte[] I;  
    
	// конструктор
	public STB34101(Cipher belt) { this(belt, null); }
        
	// конструктор
	public STB34101(Cipher belt, byte[] I) 
    {
        // сохранить переданные параметры
        this.belt = RefObject.addRef(belt); this.I = I; 
        
        // проверить корректность параметров
        if (I != null && I.length != 16) throw new IllegalArgumentException(); 
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить используемые ресурсы
        RefObject.release(belt); super.onClose(); 
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return belt.keyFactory(); } 
    // размер ключа шифрования ключей
    @Override public final int[] keySizes() { return belt.keySizes(); }
    
    // зашифровать ключ
    @Override public byte[] wrap(IRand rand, ISecretKey key, ISecretKey CEK) 
        throws IOException, InvalidKeyException
    {
        // получить значение ключа
        byte[] value = CEK.value(); if (value == null) throw new InvalidKeyException(); 
        
        // проверить размер ключа
        if (value.length < 16) throw new InvalidKeyException(); byte[] level = I; 
        
        // сгенерировать случайные данные
        if (I == null) { level = new byte[16]; rand.generate(level, 0, level.length); }
        
        // объединить ключ с заголовком
        byte[] wrapped = Array.concat(value, level); int n = (wrapped.length + 15) / 16;
            
        // выделить вспомогательные буферы
        byte[] r = new byte[16]; byte[] s = new byte[16]; 
        
        // для всех шагов алгоритма
        for (int i = 0; i < 2 * n; i++)
        {
            // скопировать первый блок ключа
            System.arraycopy(wrapped, 0, s, 0, 16);

            // для всех непоследних блоков ключа
            for (int j = 1; j < n - 1; j++)
            {
                // выполнить поразрядное сложение
                for (int k = 0; k < 16; k++) s[k] ^= wrapped[j * 16 + k]; 
            }
            // закодировать номер шага
            Convert.fromInt32(i + 1, ENDIAN, r, 0); 

            // обнулить неиспользуемые байты
            for (int j = 4; j < 16; j++) r[j] = 0; 

            // выполнить поразрядное сложение
            for (int j = 0; j < 16; j++) r[j] ^= wrapped[wrapped.length - 16 + j]; 

            // зашифровать сумму
            belt.encrypt(key, PaddingMode.NONE, s, 0, s.length, wrapped, wrapped.length - 16);

            // выполнить поразрядное сложение
            for (int j = 0; j < 16; j++) wrapped[wrapped.length - 16 + j] ^= r[j];

            // выполнить сдвиг в сторону младших разрядов
            System.arraycopy(wrapped, 16, wrapped, 0, wrapped.length - 16);

            // сохранить сумму в последних байтах
            System.arraycopy(s, 0, wrapped, wrapped.length - 16, 16);
        }
        return wrapped; 
    }
    // расшифровать ключ
    @Override public ISecretKey unwrap(ISecretKey key, 
        byte[] wrapped, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
    {
        // проверить размер данных
        if (wrapped.length < 32) throw new IOException(); 

        // определить число шагов алгоритма
        int n = (wrapped.length + 15) / 16; wrapped = wrapped.clone(); 
        
        // выделить вспопмогательные буферы
        byte[] r = new byte[16]; byte[] s = new byte[16];         

        // для всех шагов алгоритма
        for (int i = 2 * n - 1; i >= 0; i--)
        {
            // скопировать последние 16 байтов
            System.arraycopy(wrapped, wrapped.length - 16, s, 0, 16);

            // выполнить сдвиг в сторону старших разрядов
            System.arraycopy(wrapped, 0, wrapped, 16, wrapped.length - 16);

            // закодировать номер шага
            Convert.fromInt32(i + 1, ENDIAN, r, 0); 

            // обнулить неиспользуемые байты
            for (int j = 4; j < 16; j++) r[j] = 0; 

            // выполнить поразрядное сложение
            for (int j = 0; j < 16; j++) r[j] ^= wrapped[wrapped.length - 16 + j]; 

            // зашифровать последние байты
            belt.encrypt(key, PaddingMode.NONE, s, 0, s.length, wrapped, wrapped.length - 16);

            // выполнить поразрядное сложение
            for (int j = 0; j < 16; j++) wrapped[wrapped.length - 16 + j] ^= r[j];

            // для всех непоследних блоков ключа
            for (int j = 1; j < n - 1; j++)
            {
                // выполнить поразрядное сложение
                for (int k = 0; k < 16; k++) s[k] ^= wrapped[j * 16 + k]; 
            }
            // скопировать сумму в первый блок
            System.arraycopy(s, 0, wrapped, 0, 16); 
        }
        // указать заголовок ключа
        byte[] level = Arrays.copyOfRange(wrapped, wrapped.length - 16, wrapped.length); 
        
        // проверить совпадение заголовка
        if (I != null && !Arrays.equals(I, level)) throw new IOException();

        // указать значение ключа
        return keyFactory.create(Arrays.copyOf(wrapped, wrapped.length - 16)); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(KeyWrap keyWrap) throws Exception
    {
        // указать генератор случайных данных
        try (Test.Rand rand = new Test.Rand(new byte[] {
            (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
            (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
            (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
            (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
        })){
            // выполнить тест
            knownTest(rand, keyWrap, new byte[] {
                (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6
            }, new byte[] {
                (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D    
            }, new byte[] {
                (byte)0x49, (byte)0xA3, (byte)0x8E, (byte)0xE1, 
                (byte)0x08, (byte)0xD6, (byte)0xC7, (byte)0x42, 
                (byte)0xE5, (byte)0x2B, (byte)0x77, (byte)0x4F, 
                (byte)0x00, (byte)0xA6, (byte)0xEF, (byte)0x98, 
                (byte)0xB1, (byte)0x06, (byte)0xCB, (byte)0xD1, 
                (byte)0x3E, (byte)0xA4, (byte)0xFB, (byte)0x06, 
                (byte)0x80, (byte)0x32, (byte)0x30, (byte)0x51, 
                (byte)0xBC, (byte)0x04, (byte)0xDF, (byte)0x76, 
                (byte)0xE4, (byte)0x87, (byte)0xB0, (byte)0x55, 
                (byte)0xC6, (byte)0x9B, (byte)0xCF, (byte)0x54, 
                (byte)0x11, (byte)0x76, (byte)0x16, (byte)0x9F, 
                (byte)0x1D, (byte)0xC9, (byte)0xF6, (byte)0xC8
            });
        }
        // указать генератор случайных данных
        try (Test.Rand rand = new Test.Rand(new byte[] {
            (byte)0xB5, (byte)0xEF, (byte)0x68, (byte)0xD8, 
            (byte)0xE4, (byte)0xA3, (byte)0x9E, (byte)0x56, 
            (byte)0x71, (byte)0x53, (byte)0xDE, (byte)0x13, 
            (byte)0xD7, (byte)0x22, (byte)0x54, (byte)0xEE 
        })){
            // выполнить тест
            knownTest(rand, keyWrap, new byte[] {
                (byte)0x92, (byte)0xBD, (byte)0x9B, (byte)0x1C, 
                (byte)0xE5, (byte)0xD1, (byte)0x41, (byte)0x01, 
                (byte)0x54, (byte)0x45, (byte)0xFB, (byte)0xC9, 
                (byte)0x5E, (byte)0x4D, (byte)0x0E, (byte)0xF2, 
                (byte)0x68, (byte)0x20, (byte)0x80, (byte)0xAA, 
                (byte)0x22, (byte)0x7D, (byte)0x64, (byte)0x2F, 
                (byte)0x26, (byte)0x87, (byte)0xF9, (byte)0x34, 
                (byte)0x90, (byte)0x40, (byte)0x55, (byte)0x11
            }, new byte[] {
                (byte)0x92, (byte)0x63, (byte)0x2E, (byte)0xE0, 
                (byte)0xC2, (byte)0x1A, (byte)0xD9, (byte)0xE0, 
                (byte)0x9A, (byte)0x39, (byte)0x34, (byte)0x3E, 
                (byte)0x5C, (byte)0x07, (byte)0xDA, (byte)0xA4, 
                (byte)0x88, (byte)0x9B, (byte)0x03, (byte)0xF2, 
                (byte)0xE6, (byte)0x84, (byte)0x7E, (byte)0xB1, 
                (byte)0x52, (byte)0xEC, (byte)0x99, (byte)0xF7, 
                (byte)0xA4, (byte)0xD9, (byte)0xF1, (byte)0x54    
            }, new byte[] {
                (byte)0xE1, (byte)0x2B, (byte)0xDC, (byte)0x1A, 
                (byte)0xE2, (byte)0x82, (byte)0x57, (byte)0xEC, 
                (byte)0x70, (byte)0x3F, (byte)0xCC, (byte)0xF0, 
                (byte)0x95, (byte)0xEE, (byte)0x8D, (byte)0xF1, 
                (byte)0xC1, (byte)0xAB, (byte)0x76, (byte)0x38, 
                (byte)0x9F, (byte)0xE6, (byte)0x78, (byte)0xCA, 
                (byte)0xF7, (byte)0xC6, (byte)0xF8, (byte)0x60, 
                (byte)0xD5, (byte)0xBB, (byte)0x9C, (byte)0x4F,
                (byte)0xF3, (byte)0x3C, (byte)0x65, (byte)0x7B, 
                (byte)0x63, (byte)0x7C, (byte)0x30, (byte)0x6A, 
                (byte)0xDD, (byte)0x4E, (byte)0xA7, (byte)0x79, 
                (byte)0x9E, (byte)0xB2, (byte)0x3D, (byte)0x31    
            }); 
        }
    }
}