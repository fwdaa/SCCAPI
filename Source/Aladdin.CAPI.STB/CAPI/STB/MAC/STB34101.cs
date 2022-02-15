using System;

///////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки BELT
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.MAC
{
    public class STB34101 : BlockMac
    {
        // алгоритм шифрования блока и используемый ключ
        private CAPI.Cipher belt; private ISecretKey key; 
        // текущее хэш-значение
        private byte[] hash = new byte[16];
    
	    // конструктор
	    public STB34101(CAPI.Cipher belt) 
        { 
            // сохранить переданные параметры
            this.belt = RefObject.AddRef(belt); this.key = null; 
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(key); RefObject.Release(belt); base.OnDispose(); 
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return belt.KeyFactory; }} 
        // размеры ключей
	    public override int[] KeySizes { get { return belt.KeySizes; }}
    
	    // размер MAC-значения в байтах
	    public override int MacSize { get { return 8; }}

	    // размер блока алгоритма хэширования
	    public override int BlockSize { get { return 16; }}

	    ///////////////////////////////////////////////////////////////////////////
	    // Вычисление имитовставки
	    ///////////////////////////////////////////////////////////////////////////
	    public override void Init(ISecretKey key) 
	    {
            // освободить выделенные ресурсы
            RefObject.Release(this.key); this.key = null; 

		    // инициализировать алгоритм
		    base.Init(key); this.key = RefObject.AddRef(key); 
            
		    // инициализировать хэш-значение
            for (int i = 0; i < hash.Length; i++) hash[i] = 0; 
	    }
	    protected override void Update(byte[] data, int dataOff)
	    {
		    // сложить хэш-значение со входным текстом
		    for (int i = 0; i < hash.Length; i++) hash[i] ^= data[i]; 
        
		    // зашифровать хэш-значение
		    belt.Encrypt(key, PaddingMode.None, hash, 0, hash.Length, hash, 0); 
	    }
	    protected override void Finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	    {
		    // установить значение переменной R
		    byte[] R = new byte[16]; belt.Encrypt(key, PaddingMode.None, R, 0, R.Length, R, 0);

            // добавить входные данные
            for (int i = 0; i < dataLen; i++) hash[i] ^= data[dataOff + i]; 

		    // для неполного блока
		    if (dataLen < hash.Length) { hash[dataLen] ^= 0x80; 
        
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
		    belt.Encrypt(key, PaddingMode.None, hash, 0, hash.Length, hash, 0); 
            
            // вернуть имитовставку
		    Array.Copy(hash, 0, buf, bufOff, 8);

            // освободить выделенные ресурсы
            RefObject.Release(key); key = null; 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Тест известного ответа
	    ///////////////////////////////////////////////////////////////////////////
        public static void Test(Mac macAlgorithm) 
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
            KnownTest(macAlgorithm, key, 1, new byte[] {
                (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                (byte)0x58 
            }, new byte[] {
                (byte)0x72, (byte)0x60, (byte)0xDA, (byte)0x60, 
                (byte)0x13, (byte)0x8F, (byte)0x96, (byte)0xC9
            }); 
            KnownTest(macAlgorithm, key, 1, new byte[] {
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
}
