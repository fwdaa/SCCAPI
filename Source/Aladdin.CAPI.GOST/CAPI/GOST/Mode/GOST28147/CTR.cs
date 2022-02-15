namespace Aladdin.CAPI.GOST.Mode.GOST28147
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим CTR
    ///////////////////////////////////////////////////////////////////////////////
    public class CTR : CAPI.Mode.CTR
    {
        // режим смены ключа
        private KeyDerive keyMeshing;
    
        // конструктор
	    public CTR(CAPI.Cipher engine, CipherMode.CTR parameters, 
            KeyDerive keyMeshing) : base(engine, parameters)
	    { 
            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); 
	    }
        // конструктор
	    public CTR(CAPI.Cipher engine, CipherMode.CTR parameters) 

            // сохранить переданные параметры
            : base(engine, parameters) { this.keyMeshing = null; }

        // деструктор
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(keyMeshing); base.OnDispose();
        }
        // преобразование зашифрования
        protected override CAPI.Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CTR parameters = (CipherMode.CTR)Mode; 

            // преобразование зашифрования
            return new CTR_ENC(Engine, keyMeshing, key, parameters); 
        }
        // преобразование расшифрования
        protected override CAPI.Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CTR parameters = (CipherMode.CTR)Mode; 

            // преобразование расшифрования
            return new CTR_ENC(Engine, keyMeshing, key, parameters); 
        }
    }
}
