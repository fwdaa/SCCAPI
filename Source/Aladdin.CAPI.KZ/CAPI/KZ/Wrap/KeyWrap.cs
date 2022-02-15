using System;
using System.IO;

namespace Aladdin.CAPI.KZ.Wrap
{
    ////////////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ключа
    ////////////////////////////////////////////////////////////////////////////////
    public class KeyWrap : CAPI.KeyWrap
    {
        // алгоритм шифрования
        private CAPI.Cipher gost28147; private byte[] spc; 

        // конструктор
        public KeyWrap(CAPI.Cipher gost28147, byte[] spc)
        {
            // сохранить переданные параметры
            this.gost28147 = RefObject.AddRef(gost28147); this.spc = spc; 
        }
        // освободить ресурсы
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(gost28147); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return gost28147.KeyFactory; }}
        // размер ключа алгоритма
        public override int[] KeySizes { get { return gost28147.KeySizes; }}
    
	    // зашифровать ключ
	    public override byte[] Wrap(IRand rand, ISecretKey key, ISecretKey CEK)
        {
            // проверить наличие значения
            if (CEK.Value == null) throw new InvalidKeyException(); 
        
            // проверить размер ключа
            if (CEK.Length != 32) throw new InvalidKeyException(); 
        
            // указать случайные данные
            byte[] spc = this.spc; if (spc == null) 
            { 
                // сгенерировать случайные данные
                spc = new byte[8]; rand.Generate(spc, 0, 8); 
            }
            // выполнить конкатенацию данных
            byte[] data = Arrays.Concat(spc, CEK.Value); 
        
            // зашифровать данные
            return gost28147.Encrypt(key, PaddingMode.None, data, 0, data.Length); 
        }
	    // расшифровать ключ
        public override ISecretKey Unwrap(ISecretKey key, byte[] wrappedCEK, SecretKeyFactory keyFactory) 
        {
            // проверить наличие значения
            if (wrappedCEK.Length != 40) throw new InvalidDataException(); 

            // расшифровать данные
            byte[] data = gost28147.Decrypt(key, PaddingMode.None, wrappedCEK, 0, wrappedCEK.Length); 

            // проверить совпадение параметров
            if (spc != null && !Arrays.Equals(spc, 0, data, 0, 8))
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException(); 
            }
            // вернуть расшифрованный ключ
            return keyFactory.Create(Arrays.CopyOf(data, 8, 32)); 
        }
    }
}
