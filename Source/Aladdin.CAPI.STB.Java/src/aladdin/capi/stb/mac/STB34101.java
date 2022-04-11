package aladdin.capi.stb.mac;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки BELT
///////////////////////////////////////////////////////////////////////////
public class STB34101 extends BlockMac
{
    // алгоритм шифрования блока и используемый ключ
    private final Cipher belt; private ISecretKey key; 
    // текущее хэш-значение
    private final byte[] hash = new byte[16];
    
	// конструктор
	public STB34101(Cipher belt) 
    { 
        // сохранить переданные параметры
        this.belt = RefObject.addRef(belt); key = null; 
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить используемые ресурсы
        RefObject.release(key); RefObject.release(belt); super.onClose(); 
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return belt.keyFactory(); } 
    
	// размер MAC-значения в байтах
	@Override public int macSize() { return 8; }
	// размер блока алгоритма хэширования
	@Override public int blockSize() { return 16; }

	///////////////////////////////////////////////////////////////////////////
	// Вычисление имитовставки
	///////////////////////////////////////////////////////////////////////////
	@Override public void init(ISecretKey key) throws IOException, InvalidKeyException
	{ 
        // освободить выделенные ресурсы
        RefObject.release(this.key); this.key = null; 
        
		// инициализировать алгоритм
		super.init(key); this.key = RefObject.addRef(key); 
        
		// инициализировать хэш-значение
        for (int i = 0; i < hash.length; i++) hash[i] = 0; 
	}
	@Override protected void update(byte[] data, int dataOff) throws IOException
	{
		// сложить хэш-значение со входным текстом
		for (int i = 0; i < hash.length; i++) hash[i] ^= data[i]; 
        try { 
            // зашифровать хэш-значение
            belt.encrypt(key, PaddingMode.NONE, hash, 0, hash.length, hash, 0);
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new IOException(e); }
	}
	@Override protected void finish(byte[] data, 
        int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
	{
        // добавить входные данные
        for (int i = 0; i < dataLen; i++) hash[i] ^= data[dataOff + i]; 
        try { 
            // установить значение переменной R
            byte[] R = new byte[16]; belt.encrypt(key, PaddingMode.NONE, R, 0, R.length, R, 0);

            // для неполного блока
            if (dataLen < hash.length) { hash[dataLen] ^= 0x80; 

                // прибавить Fi_2(R)
                for (int i = 0; i < 4; i++)
                {
                    hash[i +  0] ^= R[i + 12]; 
                    hash[i +  0] ^= R[i +  0]; 
                    hash[i +  4] ^= R[i +  0]; 
                    hash[i +  8] ^= R[i +  4]; 
                    hash[i + 12] ^= R[i +  8]; 
                }
            }
            // прибавить Fi_1(R)
            else for (int i = 0; i < 4; i++)
            {
                hash[i +  0] ^= R[i +  4]; 
                hash[i +  4] ^= R[i +  8]; 
                hash[i +  8] ^= R[i + 12]; 
                hash[i + 12] ^= R[i +  0]; 
                hash[i + 12] ^= R[i +  4]; 
            }
            // зашифровать хэш-значение
            belt.encrypt(key, PaddingMode.NONE, hash, 0, hash.length, hash, 0); 
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new IOException(e); }
        
        // вернуть имитовставку
        System.arraycopy(hash, 0, buf, bufOff, 8);

        // освободить выделенные ресурсы
        RefObject.release(key); key = null; 
    }
	///////////////////////////////////////////////////////////////////////////
	// Тест известного ответа
	///////////////////////////////////////////////////////////////////////////
    public static void test(Mac macAlgorithm) throws Exception
    {
        byte[] key = new byte[] {
            (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
            (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
            (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
            (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
            (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
            (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
            (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
            (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6		
        }; 
        knownTest(macAlgorithm, key, 1, new byte[] {
            (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
            (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
            (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
            (byte)0x58 
        }, new byte[] {
            (byte)0x72, (byte)0x60, (byte)0xDA, (byte)0x60, 
            (byte)0x13, (byte)0x8F, (byte)0x96, (byte)0xC9
        }); 
        knownTest(macAlgorithm, key, 1, new byte[] {
            (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
            (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
            (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
            (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
            (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
            (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
            (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
            (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
            (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
            (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
            (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
            (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
        }, new byte[] {
            (byte)0x2D, (byte)0xAB, (byte)0x59, (byte)0x77, 
            (byte)0x1B, (byte)0x4B, (byte)0x16, (byte)0xD0
        }); 
    }
}
