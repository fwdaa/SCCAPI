using System;

namespace Aladdin.CAPI.MAC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм вычисления имитовставки OMAC1
    ///////////////////////////////////////////////////////////////////////////////
    public class OMAC1 : CBCMAC1
    {
        // блочный алгоритм шифрования 
        private Cipher engine; private byte[] xor; private byte[] xorK1; 

        // фиксированные константы
        private static readonly byte[] Xor64 = new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x1B,
        }; 
        private static readonly byte[] Xor128 = new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x87,
        }; 
        // создать алгоритм
        public static OMAC1 Create(IBlockCipher blockCipher, byte[] iv)
        {
            // указать размер имитовставки по умолчанию
            return Create(blockCipher, iv, blockCipher.BlockSize / 2); 
        }
        // создать алгоритм
        public static OMAC1 Create(IBlockCipher blockCipher, byte[] iv, int macSize)
        {
            // проверить корректность параметров
            if (macSize > blockCipher.BlockSize) throw new ArgumentException();

            // создать режим ECB
            using (Cipher engine = blockCipher.CreateBlockMode(new CipherMode.ECB()))
            {
                // создать режим CBC
                using (Cipher modeCBC = blockCipher.CreateBlockMode(new CipherMode.CBC(iv)))
                {
                    // создать алгоритм вычисления имитовставки OMAC1
                    return new OMAC1(modeCBC, engine, macSize); 
                }
            }
        }
        // конструктор
	    public OMAC1(Cipher modeCBC, Cipher engine, int macSize) 

            // вызвать базовую функцию
            : base(modeCBC, PaddingMode.None, macSize) 
        {
            switch (modeCBC.BlockSize)
            {
            // указать значение дополнения
            case 8: xor = Xor64; break; case 16: xor = Xor128; break;

            // при ошибке выбросить исключение
            default: throw new ArgumentException(); 
            }
            // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); 
        }  
        // конструктор
	    protected OMAC1(Cipher modeCBC, int macSize) : this(modeCBC, null, macSize) {}

        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(engine); base.OnDispose();
        }
	    // инициализировать алгоритм
	    public override void Init(ISecretKey key) 
        {
            // создать дополнительный ключ
            base.Init(key); xorK1 = CreateXorK1(key); 
        }
	    // завершить преобразование
	    protected override void Finish(
            byte[] data, int dataOff, int dataLen, byte[] mac, int macOff)
        {
            // скопировать последний блок
            byte[] buffer = new byte[BlockSize]; Array.Copy(data, 0, buffer, 0, dataLen); 
        
            // создать дополнительный ключ
            byte[] K = GetXorK1(); if (dataLen < buffer.Length)
            { 
                // выполнить инверсию бита
                K = CreateXorK2(K); buffer[dataLen] ^= 0x80;
            }
            // добавить дополнительный ключ
            for (int i = 0; i < buffer.Length; i++) buffer[i] ^= K[i]; 
            
            // обработать блок
            base.Finish(buffer, 0, buffer.Length, mac, macOff); 
        }
        // получить дополнительный ключ
        protected virtual byte[] GetXorK1() { return xorK1; }

        // создать дополнительный ключ
        protected virtual byte[] CreateXorK1(ISecretKey key)
        {
            // проверить корректность параметров
            if (engine == null) throw new InvalidOperationException(); 

            // создать нулевой блок
            byte[] K1 = new byte[BlockSize]; 
        
            // зашифровать нулевой блок
            engine.Encrypt(key, PaddingMode.None, K1, 0, K1.Length, K1, 0); 

            // создать дополнительный ключ
            return CreateXorK2(K1); 
        }
        // создать дополнительный ключ
        private byte[] CreateXorK2(byte[] K1)
        {
            // создать нулевой блок
            byte[] K2 = (byte[])K1.Clone(); bool pad = ((K1[0] & 0x80) != 0);
                
            // для всех байтов блока
            for (int i = 0; i < K1.Length; i++)
            {
                // определить операнд с младшими битами
                byte right = (i < K1.Length - 1) ? K1[i + 1] : (byte)0; 

                // выполнить сдвиг влево
                K2[i] = (byte)((K1[i] << 1) | (right >> 7)); 

                // выполнить сложение
                if (pad) K2[i] ^= xor[i];
            }
            return K2; 
        }
    }
}
