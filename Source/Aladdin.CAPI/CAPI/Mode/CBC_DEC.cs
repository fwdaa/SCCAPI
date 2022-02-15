using System;
using System.IO;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования CBC
    ///////////////////////////////////////////////////////////////////////////////
    public class CBC_DEC : BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private Cipher engine; private CipherMode.CBC parameters;
    
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private ISecretKey key; private Transform decryption; private byte[] iv;

        // конструктор
        public CBC_DEC(Cipher engine, ISecretKey key, CipherMode.CBC parameters) : base(engine.BlockSize)
        {
            // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); this.parameters = parameters; 

            // сохранить параметры 
            this.key = RefObject.AddRef(key); decryption = null; 
        }
        // конструктор
        public CBC_DEC(Cipher engine, ISecretKey key, byte[] iv) 
        
            // сохранить переданные параметры
            : this(engine, key, new CipherMode.CBC(iv)) {}  
        
        // освободить выделенные ресурсы
        protected override void OnDispose()  
        { 
            // освободить выделенные ресурсы
            RefObject.Release(decryption); RefObject.Release(key);
        
            // освободить выделенные ресурсы
            RefObject.Release(engine); base.OnDispose(); 
        } 
        // параметры шифрования
        public CipherMode.CBC Parameters { get { return parameters; }}
    
        // инициализировать алгоритм
        public override void Init() 
        { 
            // выполнить инициализацию
            iv = (byte[])parameters.IV.Clone(); ResetKey(key); 
        }  
        protected override void Update(byte[] data, int dataOff, byte[] buf, int bufOff)
        {
	        // сохранить зашифрованный текст
	        byte[] copy = new byte[BlockSize]; Array.Copy(data, dataOff, copy, 0, copy.Length);

	        // расшифровать зашифрованный текст
	        decryption.Update(data, dataOff, engine.BlockSize, buf, bufOff);

	        // расшифрованный текст ^= регистр  
	        for (int j = 0; j < copy.Length; j++) buf[bufOff + j] ^= iv[j];
	    
	        // выполнить сдвиг регистра
	        Array.Copy(iv, copy.Length, iv, 0, iv.Length - copy.Length); 

		    // сохранить зашифрованный текст в регистре
		    Array.Copy(copy, 0, iv, iv.Length - copy.Length, copy.Length); 
        }
        public override int Finish(
	        byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
        {
	        // проверить корректность данных
	        if ((dataLen % BlockSize) != 0) throw new InvalidDataException();

	        // преобразовать полные блоки
	        Update(data, dataOff, dataLen, buf, bufOff); return dataLen; 
        }
        // переустановить ключ
        protected void ResetKey(ISecretKey key) 
        {
            // освободить выделенные ресурсы
            RefObject.Release(decryption); decryption = null;  

            // создать алгоритм расшифрования блока
            decryption = engine.CreateDecryption(key, PaddingMode.None); 

            // выполнить инициализацию
            decryption.Init();
        }  
        // регистр обратной связи
        protected byte[] IV { get { return iv; }}
    }
}
