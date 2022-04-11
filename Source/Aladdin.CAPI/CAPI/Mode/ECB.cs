using System;
using System.IO;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим ECB
    ///////////////////////////////////////////////////////////////////////////////
    public class ECB : BlockMode
    { 
        // алгоритм шифрования блока
        private Cipher engine; 

        // конструктор
	    public ECB(Cipher engine, PaddingMode padding) : base(padding)
        { 
            // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); 
        }
        // деструктор
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(engine); base.OnDispose(); 
        }
        // режим шифрования 
	    public override CipherMode Mode { get { return new CipherMode.ECB(); }}
  
        // тип ключа
        public override SecretKeyFactory KeyFactory  { get { return engine.KeyFactory; }}
        // размер режима алгоритма
	    public override int BlockSize { get { return engine.BlockSize; }}

        // преобразование зашифрования
        protected override Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразование зашифрования
            return new ECB_ENC(engine, key); 
        }
        // преобразование расшифрования
        protected override Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразование расшифрования
            return new ECB_DEC(engine, key); 
        }
        // алгоритм шифрования блока
	    protected Cipher Engine { get { return engine; }} 
    }
}
