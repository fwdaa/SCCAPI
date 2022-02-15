using System; 

namespace Aladdin.CAPI.GOST.Mode.GOSTR3412
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим CTR
    ///////////////////////////////////////////////////////////////////////////////
    public class CTR : CAPI.Mode.CTR
    {
        // режим смены ключа и размер смены ключа
        private KeyDerive keyMeshing; private int N; 
    
        // конструктор
	    public CTR(CAPI.Cipher engine, CipherMode.CTR parameters, 
            KeyDerive keyMeshing, int N) : base(engine, parameters)
	    { 
            // проверить корректность параметров
            if ((N % engine.BlockSize) != 0) throw new ArgumentException(); 

            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); this.N = N; 
	    }
        // конструктор
	    public CTR(CAPI.Cipher engine, CipherMode.CTR parameters) 

            // сохранить переданные параметры
            : base(engine, parameters) { this.keyMeshing = null; N = 0; }

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

            // преобразование расшифрования
            return new CTR_ENC(Engine, keyMeshing, N, key, parameters); 
        }
        // преобразование расшифрования
        protected override CAPI.Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CTR parameters = (CipherMode.CTR)Mode; 

            // преобразование расшифрования
            return new CTR_ENC(Engine, keyMeshing, N, key, parameters); 
        }
    }
}