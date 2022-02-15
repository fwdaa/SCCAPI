using System;
using System.IO;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования CBC
    ///////////////////////////////////////////////////////////////////////////////
    public class CBC_ENC : BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private Cipher engine; private CipherMode.CBC parameters;
    
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private ISecretKey key; private Transform encryption; private byte[] iv;

        // конструктор
        public CBC_ENC(Cipher engine, ISecretKey key, CipherMode.CBC parameters) : base(engine.BlockSize)
        {
            // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); this.parameters = parameters;

            // сохранить параметры 
            this.key = RefObject.AddRef(key); encryption = null; 
        }
        // конструктор
        public CBC_ENC(Cipher engine, ISecretKey key, byte[] iv) 
        
            // сохранить переданные параметры
            : this(engine, key, new CipherMode.CBC(iv)) {}  
        
        // освободить выделенные ресурсы
        protected override void OnDispose()  
        { 
            // освободить выделенные ресурсы
            RefObject.Release(encryption); RefObject.Release(key);
        
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
	        // регистр ^= расшифрованный текст 
	        for (int j = 0; j < BlockSize; j++) iv[j] ^= data[dataOff + j];

	        // зашифровать регистр 
	        encryption.Update(iv, 0, engine.BlockSize, buf, bufOff);

	        // выполнить сдвиг регистра
	        Array.Copy(iv, BlockSize, iv, 0, iv.Length - BlockSize); 

            // сохранить зашифрованные данные в регистре
	        Array.Copy(buf, bufOff, iv, iv.Length - BlockSize, BlockSize); 
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
