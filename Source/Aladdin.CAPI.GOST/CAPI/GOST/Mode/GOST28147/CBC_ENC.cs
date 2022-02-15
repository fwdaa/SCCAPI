﻿using System;

namespace Aladdin.CAPI.GOST.Mode.GOST28147
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования CBC
    ///////////////////////////////////////////////////////////////////////////////
    public class CBC_ENC : CAPI.Mode.CBC_ENC
    {
        // алгоритм смены ключа и размер смены ключа
        private KeyDerive keyMeshing; private int N;
        // текущий ключ и накопленный размер
        private ISecretKey currentKey; private int length; 

        // конструктор
        public CBC_ENC(CAPI.Cipher engine, KeyDerive keyMeshing, ISecretKey key, 
            CipherMode.CBC parameters) : base(engine, key, parameters)
        { 
            // сохранить переданные параметры
            currentKey = RefObject.AddRef(key); N = (keyMeshing != null) ? 1024 : 0; 
        
            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); 
        } 
        // конструктор
        public CBC_ENC(CAPI.Cipher engine, ISecretKey key, 
            CipherMode.CBC parameters) : base(engine, key, parameters)
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
