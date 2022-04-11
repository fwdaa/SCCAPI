﻿using System;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим OFB
    ///////////////////////////////////////////////////////////////////////////////
	public class OFB : BlockMode
    { 
        // алгоритм шифрования блока и параметры режима
        private Cipher engine; private CipherMode.OFB parameters; 
    
        // конструктор
	    public OFB(Cipher engine, CipherMode.OFB parameters) : base(PaddingMode.None)
	    { 
            // проверить корректность данных
            if ((parameters.IV.Length % engine.BlockSize) != 0)
            {
                // при ошибке выбросить исключение
                throw new ArgumentException(); 
            }
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
        protected override CAPI.Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразование зашифрования
            return new OFB_ENC(engine, key, parameters); 
        }
        // преобразование расшифрования
        protected override CAPI.Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразование расшифрования
            return new OFB_ENC(engine, key, parameters); 
        }
        // алгоритм шифрования блока
	    protected Cipher Engine { get { return engine; }}   
    }
}
