using System;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Поточный алгоритм шифрования на основе 1-битного OFB
    ///////////////////////////////////////////////////////////////////////////////
    public class OFB1 : Cipher
    {
        // блочный алгоритм шифрования и синхропосылка
        private Cipher engine; private byte[] iv; 
    
        // конструктор
        public OFB1(Cipher engine, byte[] iv)
        {
            // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); this.iv = iv; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(engine); base.OnDispose(); 
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory  { get { return engine.KeyFactory; }}
    
        protected override Transform CreateEncryption(ISecretKey key) 
        {
            // создать преобразование зашифрования
            return new OFB1_ENC(engine, key, iv); 
        }
        protected override Transform CreateDecryption(ISecretKey key) 
        {
            // создать преобразование расшифрования
            return new OFB1_ENC(engine, key, iv); 
        }
    }
}
