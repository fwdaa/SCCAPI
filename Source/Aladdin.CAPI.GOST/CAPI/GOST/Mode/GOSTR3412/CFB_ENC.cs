using System;

namespace Aladdin.CAPI.GOST.Mode.GOSTR3412
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования CFB
    ///////////////////////////////////////////////////////////////////////////////
    public class CFB_ENC : CAPI.Mode.CFB_ENC
    {
        // алгоритм смены ключа и размер смены ключа
        private KeyDerive keyMeshing; private int N;
        // текущий ключ и накопленный размер
        private ISecretKey currentKey; private int length; 

        // конструктор
        public CFB_ENC(CAPI.Cipher engine, KeyDerive keyMeshing, int N, 
            ISecretKey key, CipherMode.CFB parameters) : base(engine, key, parameters)
        { 
            // проверить корректность параметров
            if ((N % engine.BlockSize) != 0) throw new ArgumentException(); 

            // сохранить переданные параметры
            currentKey = RefObject.AddRef(key); this.N = N; 
        
            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); 
        } 
        // конструктор
        public CFB_ENC(CAPI.Cipher engine, ISecretKey key, 
            CipherMode.CFB parameters) : base(engine, key, parameters)
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
        public override void Init() { base.Init(); length = 0; }
    
        // обработать блок
        protected override void Update(byte[] data, int dataOff, byte[] buf, int bufOff)
        {
            // обработать полный блок
            base.Update(data, dataOff, buf, bufOff); 
        
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
    }
}
