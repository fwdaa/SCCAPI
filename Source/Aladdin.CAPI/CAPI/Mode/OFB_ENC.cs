using System;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим преобразования OFB
    ///////////////////////////////////////////////////////////////////////////////
    public class OFB_ENC : BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private Cipher engine; private CipherMode.OFB parameters;
    
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private ISecretKey key; private CAPI.Transform encryption; private byte[] iv;

        // конструктор
        public OFB_ENC(Cipher engine, ISecretKey key, CipherMode.OFB parameters) : base(engine.BlockSize)
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
        public CipherMode.OFB Parameters { get { return parameters; }}
    
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
        
	        // выходной текст = входной текст
	        Array.Copy(data, dataOff, buf, bufOff, BlockSize);

	        // выходной текст ^= регистр 
	        for (int j = 0; j < BlockSize; j++) buf[bufOff + j] ^= encrypted[j]; 
    
            // сдвинуть регистр обратной связи
            Array.Copy(iv, encrypted.Length, iv, 0, iv.Length - encrypted.Length); 
        
            // регистр = зашифрованный текст
            Array.Copy(encrypted, 0, iv, iv.Length - encrypted.Length, encrypted.Length); 
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
