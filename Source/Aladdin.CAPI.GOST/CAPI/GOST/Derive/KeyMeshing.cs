using System; 

namespace Aladdin.CAPI.GOST.Derive
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм смены ключа
    ///////////////////////////////////////////////////////////////////////////////
    public class KeyMeshing : KeyDerive
    {
        // алгоритм шифрования блока
        private CAPI.Cipher gost28147;

        // конструктор
        public KeyMeshing(CAPI.Cipher gost28147)
        { 
            // сохранить переданные параметры
            this.gost28147 = RefObject.AddRef(gost28147); 
        }  
        // освободить ресурсы
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(gost28147); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return gost28147.KeyFactory; }} 
        // размер используемых ключей
        public override int[] KeySizes { get { return gost28147.KeySizes; }}

	    // наследовать ключ
	    public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] iv, SecretKeyFactory keyFactory, int deriveSize) 
        {
            // указать размер генерируемого ключа
            if (deriveSize < 0) deriveSize = 32; 

            // проверить размер ключа
            if (deriveSize != 32) throw new NotSupportedException(); 
        
    	    // константа для расшифрования
		    byte[] C = {
			    0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
			    0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
			    0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
			    0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
		    };
		    // выделить память для нового ключа
		    byte[] value = new byte[deriveSize]; 

            // переустановить ключ
	        gost28147.Decrypt(key, PaddingMode.None, C, 0, C.Length, value,  0);

            // создать ключ
            using (ISecretKey newKey = keyFactory.Create(value)) 
            {
                // зашифровать синхропосылку
                if (iv != null) gost28147.Encrypt(newKey, PaddingMode.None, iv, 0, iv.Length, iv, 0); 

                // увеличить счетчик ссылок
                return RefObject.AddRef(newKey);  
            }
        }
    }
}