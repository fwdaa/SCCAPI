using System;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим преобразования CTR
    ///////////////////////////////////////////////////////////////////////////////
    public class CTR_ENC : BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private Cipher engine; private CipherMode.CTR parameters;
    
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private ISecretKey key; protected CAPI.Transform encryption; private byte[] iv;

        // конструктор
        public CTR_ENC(Cipher engine, ISecretKey key, CipherMode.CTR parameters) : base(engine.BlockSize)
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
        public CipherMode.CTR Parameters { get { return parameters; }}
    
        // инициализировать алгоритм
        public override void Init() 
        { 
            // выделить память для синхропосылки
            iv = new byte[engine.BlockSize]; ResetKey(key); 
        
            // скопировать синхропосылку и инициализировать алгоритм
            Array.Copy(parameters.IV, 0, iv, 0, parameters.IV.Length); 
        }  
        protected override void Update(byte[] data, int dataOff, byte[] buf, int bufOff)
        {
            // выделить вспомогательный буфер
            byte[] encrypted = new byte[engine.BlockSize];

		    // зашифровать регистр, увеличить регистр 
		    encryption.Update(iv, 0, encrypted.Length, encrypted, 0); Increment(iv);

		    // для всех байтов
		    for (int j = 0; j < BlockSize; j++) 
            {
                // выполнить поразрядное сложение
                buf[bufOff + j] = (byte)(data[dataOff + j] ^ encrypted[j]); 
            }
	    }
        // выполнить инкремент регистра обратной связи
        protected virtual void Increment(byte[] iv)
        {
            // определить последний инкрементируемый байт
            int limit = iv.Length - parameters.CounterSize; 

	        // для всех разрядов регистра
	        for (int i = iv.Length - 1; i >= limit; i--)
	        {
		        // увеличить разряд регистра
		        iv[i] = (byte)(iv[i] + 1); if (iv[i] != 0) break; 
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
