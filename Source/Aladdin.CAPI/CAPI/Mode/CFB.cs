using System;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим CFB
    ///////////////////////////////////////////////////////////////////////////////
    public class CFB : BlockMode
    { 
        // алгоритм шифрования блока и параметры режима
        private Cipher engine; private CipherMode.CFB parameters; 
    
        // конструктор
	    public CFB(Cipher engine, CipherMode.CFB parameters) : base(PaddingMode.None)
	    { 
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
        // размер режима алгоритма
	    public override int BlockSize { get { 

			// получить размер блока алгоритма
			int blockSize = parameters.BlockSize; 
            
            // вернуть размер блока алгоритма
            return (blockSize > 0) ? blockSize : engine.BlockSize; 
        }}
        // преобразование зашифрования
        protected override Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразование зашифрования
            return new CFB_ENC(engine, key, parameters); 
        }
        // преобразование расшифрования
        protected override Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразование расшифрования
            return new CFB_DEC(engine, key, parameters); 
        }
        // алгоритм шифрования блока
	    protected Cipher Engine { get { return engine; }}   
    }
}
