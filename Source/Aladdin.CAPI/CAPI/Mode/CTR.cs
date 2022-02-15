using System;

namespace Aladdin.CAPI.Mode
{
	///////////////////////////////////////////////////////////////////////////////
	// Режим CTR
	///////////////////////////////////////////////////////////////////////////////
	public class CTR : BlockMode
    { 
        // алгоритм шифрования блока и параметры режима
        private Cipher engine; private CipherMode.CTR parameters; 
    
        // конструктор
	    public CTR(Cipher engine, CipherMode.CTR parameters) : base(PaddingMode.None)
	    { 
            // проверить корректность данных
            if (parameters.IV.Length > engine.BlockSize) throw new ArgumentException(); 

            // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); this.parameters = parameters; 
	    }
        // деструктор
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(engine); base.OnDispose(); 
        }
        // режим шифрования 
	    public override CipherMode Mode { get { return parameters; }}

        // тип ключа
        public override SecretKeyFactory KeyFactory  { get { return engine.KeyFactory; }}
        // размер ключей
	    public override int[] KeySizes { get { return engine.KeySizes; }}
        // размер режима алгоритма
	    public override int BlockSize { get { 

			// получить размер блока алгоритма
			int blockSize = parameters.BlockSize; 
            
            // вернуть размер блока алгоритма
            return (blockSize > 0) ? blockSize : engine.BlockSize; 
        }}
        // преобразование зашифрования
        protected override CAPI.Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразование зашифрования
            return new CTR_ENC(engine, key, parameters); 
        }
        // преобразование расшифрования
        protected override CAPI.Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразование расшифрования
            return new CTR_ENC(engine, key, parameters); 
        }
        // алгоритм шифрования блока
	    protected Cipher Engine { get { return engine; }}   

	}
}
