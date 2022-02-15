using System; 

namespace Aladdin.CAPI.GOST.Mode.GOSTR3412
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования CFB
    ///////////////////////////////////////////////////////////////////////////////
    public class CFB : CAPI.Mode.CFB
    {
        // режим смены ключа и размер смены ключа
        private KeyDerive keyMeshing; private int N; 
    
        // конструктор
	    public CFB(CAPI.Cipher engine, CipherMode.CFB parameters, 
            KeyDerive keyMeshing, int N) : base(engine, parameters)
	    { 
            // проверить корректность параметров
            if ((N % engine.BlockSize) != 0) throw new ArgumentException(); 

            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); this.N = N; 
	    }
        // конструктор
	    public CFB(CAPI.Cipher engine, CipherMode.CFB parameters) 

            // сохранить переданные параметры
            : base(engine, parameters) { this.keyMeshing = null; N = 0; }

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
            return new CFB_ENC(Engine, keyMeshing, N, key, parameters); 
        }
        // преобразование расшифрования
        protected override Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CFB parameters = (CipherMode.CFB)Mode; 

            // преобразование расшифрования
            return new CFB_DEC(Engine, keyMeshing, N, key, parameters); 
        }
    }
}