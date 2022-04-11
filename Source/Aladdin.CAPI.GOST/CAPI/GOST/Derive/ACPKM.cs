using System; 

namespace Aladdin.CAPI.GOST.Derive
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм смены ключа ACPKM
    ///////////////////////////////////////////////////////////////////////////////
    public class ACPKM : KeyDerive
    {
        // алгоритм шифрования блока
        private CAPI.Cipher cipher;

        // конструктор
        public ACPKM(CAPI.Cipher cipher)
        { 
            // сохранить переданные параметры
            this.cipher = RefObject.AddRef(cipher); 
        }  
        // освободить ресурсы
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(cipher); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return cipher.KeyFactory; }} 

	    // наследовать ключ
	    public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] iv, SecretKeyFactory keyFactory, int deriveSize) 
        {
            // указать размер генерируемого ключа
            if (deriveSize < 0) deriveSize = 32; 

            // проверить размер ключа
            if (deriveSize != 32) throw new NotSupportedException(); 
        
    	    // константа для расшифрования
		    byte[] D = {
			    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
			    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
			    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
			    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
		    };
		    // выделить память для нового ключа
		    byte[] value = new byte[deriveSize]; 

            // сгенерировать новый ключ
	        cipher.Encrypt(key, PaddingMode.None, D, 0, D.Length, value, 0);

            // создать ключ
            return keyFactory.Create(value);  
        }
    }
}