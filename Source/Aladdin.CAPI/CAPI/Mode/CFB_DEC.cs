using System;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования CFB
    ///////////////////////////////////////////////////////////////////////////////
    public class CFB_DEC : BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private Cipher engine; private CipherMode.CFB parameters;
    
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private ISecretKey key; private Transform encryption; private byte[] iv;

        // конструктор
        public CFB_DEC(Cipher engine, ISecretKey key, CipherMode.CFB parameters) : base(engine.BlockSize)
        {
            // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); this.parameters = parameters; 

            // сохранить параметры 
            this.key = RefObject.AddRef(key); encryption = null; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()  
        { 
            // освободить выделенные ресурсы
            RefObject.Release(encryption); RefObject.Release(key);
        
            // освободить выделенные ресурсы
            RefObject.Release(engine); base.OnDispose(); 
        } 
        // параметры шифрования
        public CipherMode.CFB Parameters { get { return parameters; }}
    
        // инициализировать алгоритм
        public override void Init() 
        { 
            // выполнить инициализацию
            iv = (byte[])parameters.IV.Clone(); ResetKey(key); 
        }  
        protected override void Update(byte[] data, int dataOff, byte[] buf, int bufOff)
        {
            // выделить вспомогательный буфер
            byte[] encrypted = new byte[engine.BlockSize]; 
        
            // зашифровать регистр обратной связи
            encryption.Update(iv, 0, encrypted.Length, encrypted, 0);
    
            // сдвинуть регистр обратной связи
            Array.Copy(iv, BlockSize, iv, 0, iv.Length - BlockSize); 

            // регистр = исходный зашифрованный текст
            Array.Copy(data, dataOff, iv, iv.Length - BlockSize, BlockSize); 
    
            // сложить результат шифрования с исходными данными
            for (int j = 0; j < BlockSize; j++)
            {
                // сложить результат шифрования с исходными данными
                buf[bufOff + j] = (byte)(data[dataOff + j] ^ encrypted[j]);
            }
        }
        // переустановить ключ
        protected void ResetKey(ISecretKey key) 
        {
            // освободить выделенные ресурсы
            RefObject.Release(encryption); encryption = null;  

            // создать алгоритм зашифрования блока
            encryption = engine.CreateEncryption(key, PaddingMode.None); 

            // выполнить инициализацию
            encryption.Init();
        }  
        // регистр обратной связи
        protected byte[] IV { get { return iv; }}
    }
}
