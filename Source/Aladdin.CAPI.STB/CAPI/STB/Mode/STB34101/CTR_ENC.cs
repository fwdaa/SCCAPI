using System;

namespace Aladdin.CAPI.STB.Mode.STB34101
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим преобразования CTR
    ///////////////////////////////////////////////////////////////////////////////
    public class CTR_ENC : CAPI.Mode.CTR_ENC
    {
        // конструктор
        public CTR_ENC(CAPI.Cipher engine, ISecretKey key, 
        
            // сохранить переданные параметры
            CipherMode.CTR parameters) : base(engine, key, parameters) {}

        public override void Init()
        {  
            // зашифровать синхропосылку 
            base.Init(); encryption.Update(IV, 0, IV.Length, IV, 0); 
        }
        protected override void Update(byte[] data, int dataOff, byte[] buf, int bufOff)
        {
            // выделить вспомогательный буфер
            byte[] encrypted = new byte[BlockSize]; Increment(IV);

		    // зашифровать регистр, увеличить регистр 
		    encryption.Update(IV, 0, encrypted.Length, encrypted, 0); 

		    // для всех байтов
		    for (int j = 0; j < BlockSize; j++) 
            {
                // выполнить поразрядное сложение
                buf[bufOff + j] = (byte)(data[dataOff + j] ^ encrypted[j]); 
            }
	    }
        // увеличить значение регистра
        protected override void Increment(byte[] iv)
        {
            // для всех разрядов регистра
            for (int i = 0; i < iv.Length; i++)
            {
                // увеличить разряд регистра
                iv[i] = (byte)(iv[i] + 1); if (iv[i] != 0) break; 
            }
        }
    }
}
