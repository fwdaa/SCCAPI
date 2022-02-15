namespace Aladdin.CAPI.GOST.Mode.GOST28147
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования CFB
    ///////////////////////////////////////////////////////////////////////////////
    public class CFB : CAPI.Mode.CFB
    {
        // режим смены ключа
        private KeyDerive keyMeshing;
    
        // конструктор
	    public CFB(CAPI.Cipher engine, CipherMode.CFB parameters, 
            KeyDerive keyMeshing) : base(engine, parameters)
	    { 
            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); 
	    }
        // конструктор
	    public CFB(CAPI.Cipher engine, CipherMode.CFB parameters) 

            // сохранить переданные параметры
            : base(engine, parameters) { this.keyMeshing = null; }

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
            CipherMode.CFB parameters = (CipherMode.CFB)Mode; 

            // преобразование зашифрования
            return new CFB_ENC(Engine, keyMeshing, key, parameters); 
        }
        // преобразование расшифрования
        protected override Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CFB parameters = (CipherMode.CFB)Mode; 

            // преобразование расшифрования
            return new CFB_DEC(Engine, keyMeshing, key, parameters); 
        }
    }
}