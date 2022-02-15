namespace Aladdin.CAPI.GOST.Mode.GOST28147
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим ECB
    ///////////////////////////////////////////////////////////////////////////////
    public class ECB : CAPI.Mode.ECB
    {
        // режим смены ключа
        private KeyDerive keyMeshing;
    
        // конструктор
	    public ECB(CAPI.Cipher engine, KeyDerive keyMeshing, PaddingMode padding) : base(engine, padding)
	    { 
            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); 
	    }
        // конструктор
	    public ECB(CAPI.Cipher engine, KeyDerive keyMeshing) 
            
            // сохранить переданные параметры
            : this(engine, keyMeshing, PaddingMode.Any) {}

        // конструктор
	    public ECB(CAPI.Cipher engine, PaddingMode padding) 
            
            // сохранить переданные параметры
            : base(engine, padding) { this.keyMeshing = null; }

        // конструктор
	    public ECB(CAPI.Cipher engine) : this(engine, PaddingMode.Any) {}

        // деструктор
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(keyMeshing); base.OnDispose();
        }
        // преобразование зашифрования
        protected override Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразование зашифрования
            return new ECB_ENC(Engine, keyMeshing, key); 
        }
        // преобразование расшифрования
        protected override Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразование расшифрования
            return new ECB_DEC(Engine, keyMeshing, key); 
        }
    }
}
