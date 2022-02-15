namespace Aladdin.CAPI.GOST.Mode.GOST28147
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим CBC
    ///////////////////////////////////////////////////////////////////////////////
    public class CBC : CAPI.Mode.CBC
    {
        // режим смены ключа
        private KeyDerive keyMeshing;
    
        // конструктор
	    public CBC(CAPI.Cipher engine, CipherMode.CBC parameters, 
            KeyDerive keyMeshing, PaddingMode padding) : base(engine, parameters, padding)
	    { 
            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); 
	    }
        // конструктор
	    public CBC(CAPI.Cipher engine, CipherMode.CBC parameters, KeyDerive keyMeshing)
            
            // сохранить переданные параметры
            : this(engine, parameters, keyMeshing, PaddingMode.Any) {}

        // конструктор
	    public CBC(CAPI.Cipher engine, CipherMode.CBC parameters, PaddingMode padding) 
            
            // сохранить переданные параметры
            : base(engine, parameters, padding) { this.keyMeshing = null; }

        // конструктор
	    public CBC(CAPI.Cipher engine, CipherMode.CBC parameters) 
            
            // сохранить переданные параметры
            : this(engine, parameters, PaddingMode.Any) {}

        // деструктор
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(keyMeshing); base.OnDispose();
        }
        // преобразование зашифрования
        protected override Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CBC parameters = (CipherMode.CBC)Mode; 

            // преобразование зашифрования
            return new CBC_ENC(Engine, keyMeshing, key, parameters); 
        }
        // преобразование расшифрования
        protected override Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CBC parameters = (CipherMode.CBC)Mode; 

            // преобразование расшифрования
            return new CBC_DEC(Engine, keyMeshing, key, parameters); 
        }
    }
}
