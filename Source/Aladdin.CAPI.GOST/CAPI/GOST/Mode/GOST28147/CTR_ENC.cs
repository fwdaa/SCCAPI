using System;

namespace Aladdin.CAPI.GOST.Mode.GOST28147
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим преобразовния CTR
    ///////////////////////////////////////////////////////////////////////////////
    public class CTR_ENC : CAPI.Mode.CTR_ENC
    {
        // алгоритм смены ключа и размер смены ключа
        private KeyDerive keyMeshing; private int N;
        // текущий ключ и накопленный размер
        private ISecretKey currentKey; private int length; 

        // конструктор
        public CTR_ENC(CAPI.Cipher engine, KeyDerive keyMeshing, ISecretKey key, 
            CipherMode.CTR parameters) : base(engine, key, parameters)
        { 
            // сохранить переданные параметры
            currentKey = RefObject.AddRef(key); N = (keyMeshing != null) ? 1024 : 0; 
        
            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); 
        } 
        // конструктор
        public CTR_ENC(CAPI.Cipher engine, ISecretKey key, 
            CipherMode.CTR parameters) : base(engine, key, parameters)
        { 
            // сохранить переданные параметры
            currentKey = RefObject.AddRef(key); keyMeshing = null; N = 0; 
        } 
        // освободить ресурсы
        protected override void OnDispose() 
        {
            // освободить ресурсы
            RefObject.Release(currentKey);
        
            // освободить ресурсы
            RefObject.Release(keyMeshing); base.OnDispose();
        }
        // инициализировать алгоритм
        public override void Init() { base.Init(); length = 0; 

	        // зашифровать синхропосылку
		    encryption.Update(IV, 0, IV.Length, IV, 0); 
        }
        // обработать блок
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
            // увеличить размер данных
            length += BlockSize; if (N == 0 || (length % N) != 0) return; 

            // изменить значение ключа
            using (ISecretKey key = keyMeshing.DeriveKey(currentKey, IV, currentKey.KeyFactory, 32))
            {
                // переустановить ключ
                if (key != currentKey) ResetKey(key); 

                // сохранить новый текущий ключ
                RefObject.Release(currentKey); currentKey = RefObject.AddRef(key); 
            }
        }
        protected override void Increment(byte[] iv)
        {
	        // фиксированные константы
	        uint C1 = 0x01010104; uint C2 = 0x01010101;

	        // извлечь обрабатываемый блок
	        uint N2 = Math.Convert.ToUInt32(iv, 0, GOST.Engine.GOST28147.Endian); 
	        uint N1 = Math.Convert.ToUInt32(iv, 4, GOST.Engine.GOST28147.Endian); 
            
	        // добавить фиксированные константы
		    N2 = N2 + C2; N1 = N1 + C1; if (N1 < C1) N1 = N1 + 1;
    
	        // вернуть обработанный блок
            Math.Convert.FromUInt32(N2, GOST.Engine.GOST28147.Endian, iv, 0); 
            Math.Convert.FromUInt32(N1, GOST.Engine.GOST28147.Endian, iv, 4); 
        }
    }
}
