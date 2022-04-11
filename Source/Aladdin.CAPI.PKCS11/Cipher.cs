using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования
	///////////////////////////////////////////////////////////////////////////////
	public abstract class Cipher : CAPI.Cipher
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected Cipher(Applet applet)
		 
			// сохранить переданные параметры
			{ this.applet = RefObject.AddRef(applet); } 

        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(applet); base.OnDispose();  
        }
		// используемое устройство
		public Applet Applet { get { return applet; }}

		// параметры алгоритма
		public abstract Mechanism GetParameters(Session sesssion); 

		// атрибуты ключа
		public virtual Attribute[] GetKeyAttributes(int keySize)
		{ 
			// атрибуты ключа
			return applet.Provider.SecretKeyAttributes(KeyFactory, keySize, true); 
		}
		// алгоритм зашифрования данных
		protected override Transform CreateEncryption(ISecretKey key)
		{
			// создать алгоритм зашифрования данных
			return new Encryption(this, PaddingMode.None, key); 
		}
		// алгоритм расшифрования данных
		protected override Transform CreateDecryption(ISecretKey key)
		{
			// создать алгоритм расшифрования данных
			return new Decryption(this, PaddingMode.None, key); 
		}
        // создать алгоритм шифрования ключа
        public override CAPI.KeyWrap CreateKeyWrap(PaddingMode padding)
        {
            // создать алгоритм шифрования ключа
            return new KeyWrap(this); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Алгоритм шифрования ключа на основе алгоритма шифрования
        ///////////////////////////////////////////////////////////////////////////
        private class KeyWrap : CAPI.PKCS11.KeyWrap
        {
            // используемый алгоритм шифрования
            private Cipher cipher; 

            // конструктор
            public KeyWrap(Cipher cipher) : base(cipher.Applet) 
            {	
                // сохранить переданные параметры
                this.cipher = RefObject.AddRef(cipher); 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose() 
            { 
                // освободить выделенные ресурсы
                RefObject.Release(cipher); base.OnDispose(); 
            }
            // параметры алгоритма
            protected override Mechanism GetParameters(Session sesssion, IRand rand)
            {
                // параметры алгоритма
                return cipher.GetParameters(sesssion); 
            }
            // атрибуты ключа
            protected override Attribute[] GetKeyAttributes(int keySize) 
            { 
                // атрибуты ключа
                return cipher.GetKeyAttributes(keySize); 
            } 
            // тип ключей
            public override SecretKeyFactory KeyFactory { get { return cipher.KeyFactory; }}
        }
	}
}
