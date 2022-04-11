using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Блочный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public abstract class BlockCipher : RefObject, IBlockCipher
    {
        // фабрика алгоритмов и область видимости
        private CAPI.Factory factory; private SecurityStore scope; 

        // конструктор
        public BlockCipher(CAPI.Factory factory, SecurityStore scope) 
        {
            // сохранить переданные параметры	
            this.factory = RefObject.AddRef(factory); this.scope = RefObject.AddRef(scope);
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); RefObject.Release(factory); base.OnDispose();
        }
        // фабрика алгоритмов и область видимости
        protected CAPI.Factory  Factory { get { return factory; }}
        protected SecurityStore Scope   { get { return scope;   }}
    
        // тип ключа
        public abstract SecretKeyFactory KeyFactory { get; }  
        // размер блока
        public abstract int BlockSize { get; } 
        
        // получить режим шифрования
        protected virtual CAPI.Cipher CreateBlockMode(CipherMode mode, int keyLength)
        {
            // в зависиморсти от режима
            if (mode is CipherMode.CBC) 
            {
                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new Mode.CBC(engine, (CipherMode.CBC)mode, PaddingMode.Any); 
                }
            }
            // в зависиморсти от режима
            if (mode is CipherMode.OFB) 
            {
                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new Mode.OFB(engine, (CipherMode.OFB)mode); 
                }
            }
            // в зависиморсти от режима
            if (mode is CipherMode.CFB) 
            {
                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new Mode.CFB(engine, (CipherMode.CFB)mode); 
                }
            }
            // режим не поддерживается
            throw new NotSupportedException();
        }
        // получить режим шифрования
        public virtual CAPI.Cipher CreateBlockMode(CipherMode mode)
        {
            // получить допустимые размеры ключей
            int[] keySizes = KeyFactory.KeySizes; 
        
            // при неизвестном размере ключей
            if (keySizes == CAPI.KeySizes.Unrestricted || keySizes.Length > 1)
            {
                // в зависимости от режима
                if (mode is CipherMode.ECB) return new BlockMode(this, mode); 
                if (mode is CipherMode.CBC) return new BlockMode(this, mode); 
                if (mode is CipherMode.OFB) return new BlockMode(this, mode); 
                if (mode is CipherMode.CFB) return new BlockMode(this, mode); 

                // режим не поддерживается
                throw new NotSupportedException();
            }
            // получить режим шифрования
            else return CreateBlockMode(mode, keySizes[0]); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Алгоритм шифрования с неизвестным заранее размером ключа
        ///////////////////////////////////////////////////////////////////////////
        private class BlockMode : CAPI.Cipher
        {
            // блочный алгоритм шифрования и режим
            private BlockCipher blockCipher; private CipherMode mode; 
        
            // конструктор
            public BlockMode(BlockCipher blockCipher, CipherMode mode)
            {
                // сохранить переданные параметры
                this.blockCipher = RefObject.AddRef(blockCipher); this.mode = mode; 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose() 
            {
                // освободить выделенные ресурсы
                RefObject.Release(blockCipher); base.OnDispose();
            }
            // тип ключа
            public override SecretKeyFactory KeyFactory { get { return blockCipher.KeyFactory; }}
            // размер блока
            public override int BlockSize { get { return blockCipher.BlockSize; }}
        
            // режим алгоритма
            public override CipherMode Mode { get { return mode; }}
    
            // алгоритм зашифрования данных
            public override Transform CreateEncryption(ISecretKey key, PaddingMode padding) 
            {
                // создать блочный алгоритм шифрования
                using (CAPI.Cipher blockMode = blockCipher.CreateBlockMode(mode, key.Length))
                {
                    // создать преобразование зашифрования
                    return blockMode.CreateEncryption(key, padding); 
                }
            }
            // алгоритм расшифрования данных
            public override Transform CreateDecryption(ISecretKey key, PaddingMode padding) 
            {
                // создать блочный алгоритм шифрования
                using (CAPI.Cipher blockMode = blockCipher.CreateBlockMode(mode, key.Length))
                {
                    // создать преобразование расшифрования
                    return blockMode.CreateDecryption(key, padding); 
                }
            }
        }
    }
}
