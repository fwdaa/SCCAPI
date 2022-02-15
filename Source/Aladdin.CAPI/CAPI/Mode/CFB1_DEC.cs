using System;

namespace Aladdin.CAPI.Mode
{
    ////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования 1-битного CFB
    ////////////////////////////////////////////////////////////////////////////
    public class CFB1_DEC : Transform
    {
        // зашифрование блока данных и размер блока
        private Transform encryption; private int blockSize; 	
    
        // вектор инициализации
        private byte[] initIV; private byte[] currentIV;
    
        // конструктор
        public CFB1_DEC(Cipher engine, ISecretKey key, byte[] iv)
        {
            // создать преобразование зашифрования
            encryption = engine.CreateEncryption(key, PaddingMode.None); 
            
            // сохранить синхропосылку
            initIV = (byte[])iv.Clone(); blockSize = engine.BlockSize; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(encryption); base.OnDispose(); 
        }
        // инициализировать алгоритм
        public override void Init() 
        { 
            // инициализировать алгоритм
            encryption.Init(); currentIV = (byte[])initIV.Clone(); 
        }
        // преобразовать данные
        public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) 
        {
            // скопировать исходные данные
            Array.Copy(data, dataOff, buf, bufOff, dataLen);
        
            // выделить память для результата шифрования
            byte[] encrypted = new byte[currentIV.Length]; 
        
            // для всех битов байтов
            for (int i = 0; i < dataLen; i++) for (int j = 0; j < 8; j++)
            {
                // извлечь исходный бит
                byte bit = (byte)((buf[bufOff + i] >> (7 - j)) & 1); 
                
                // зашифровать регистр обратной связи
                encryption.Update(currentIV, 0, blockSize, encrypted, 0); currentIV[0] <<= 1;
                
                // для всех байтов регистра обратной связи
                for (int k = 0; k < currentIV.Length - 1; k++)
                {
                    // выполнить сдвиг байта на одну позицию
                    currentIV[k] |= (byte)(currentIV[k + 1] >> 7); currentIV[k + 1] <<= 1;
                }
                // установить младший бит
                currentIV[currentIV.Length - 1] |= bit; 
                
                // сложить результат шифрования
                buf[bufOff + i] ^= (byte)((encrypted[0] & 0x80) >> j);
            }
            return dataLen; 
        }
        // завершить преобразование
        public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) 
        {
            // выполнить преобразование
            return Update(data, dataOff, dataLen, buf, bufOff); 
        }
    }
}
