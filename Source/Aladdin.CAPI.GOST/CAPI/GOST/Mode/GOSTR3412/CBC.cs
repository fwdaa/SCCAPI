using System; 

namespace Aladdin.CAPI.GOST.Mode.GOSTR3412
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим CBC
    ///////////////////////////////////////////////////////////////////////////////
    public class CBC : CAPI.Mode.CBC
    {
        // режим смены ключа и размер смены ключа
        private KeyDerive keyMeshing; private int N; 
    
        // конструктор
	    public CBC(CAPI.Cipher engine, CipherMode.CBC parameters, 
            KeyDerive keyMeshing, int N, PaddingMode padding) : base(engine, parameters, padding)
	    { 
            // проверить корректность параметров
            if ((N % engine.BlockSize) != 0) throw new ArgumentException(); 

            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); this.N = N; 
	    }
        // конструктор
	    public CBC(CAPI.Cipher engine, CipherMode.CBC parameters, KeyDerive keyMeshing, int N)
            
            // сохранить переданные параметры
            : this(engine, parameters, keyMeshing, N, PaddingMode.Any) {}

        // конструктор
	    public CBC(CAPI.Cipher engine, CipherMode.CBC parameters, PaddingMode padding) 
            
            // сохранить переданные параметры
            : base(engine, parameters, padding) { this.keyMeshing = null; N = 0; }

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
            return new CBC_ENC(Engine, keyMeshing, N, key, parameters); 
        }
        // преобразование расшифрования
        protected override Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CBC parameters = (CipherMode.CBC)Mode; 

            // преобразование расшифрования
            return new CBC_DEC(Engine, keyMeshing, N, key, parameters); 
        }
    }
}
