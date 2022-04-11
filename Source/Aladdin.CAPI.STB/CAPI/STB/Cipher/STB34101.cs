using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.STB.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования BELT
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class STB34101 : RefObject, IBlockCipher
    {
        // фабрика алгоритмов, область видимости и размер ключа
        private CAPI.Factory factory; private SecurityStore scope; 

        // конструктор
        public STB34101(CAPI.Factory factory, SecurityStore scope)
        {
            // сохранить переданные параметры	
            this.factory = RefObject.AddRef(factory); 

            // сохранить переданные параметры	
            this.scope = RefObject.AddRef(scope); 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); RefObject.Release(factory); base.OnDispose();
        }
        // тип ключа
        public SecretKeyFactory KeyFactory 
        { 
            get { return new Keys.STB34101(new int[] { 16, 24, 32 }); }
        }
        // размер блока
        public int BlockSize { get { return 16; }} 
        
        // получить режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode)
        {
            // в зависимости от режима
            if (mode is CipherMode.ECB) return new BlockMode(this, mode); 
            if (mode is CipherMode.CBC) return new BlockMode(this, mode); 
            if (mode is CipherMode.CFB) return new BlockMode(this, mode); 
            if (mode is CipherMode.CTR) return new BlockMode(this, mode); 
            
            // режим не поддерживается
            throw new NotSupportedException();
        }
        // получить режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode, int keyLength)
        {
            // вернуть режим шифрования ECB
            if (mode is CipherMode.ECB) 
            {
                // указать идентификатор алгоритма
                string oid = ASN1.STB.OID.stb34101_belt_ecb_256; switch (keyLength)
                {
                case 24: oid = ASN1.STB.OID.stb34101_belt_ecb_192; break; 
                case 16: oid = ASN1.STB.OID.stb34101_belt_ecb_128; break; 
                }
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CBC) 
            {
                // указать идентификатор алгоритма
                String oid = ASN1.STB.OID.stb34101_belt_cbc_256; switch (keyLength)
                {
                case 24: oid = ASN1.STB.OID.stb34101_belt_cbc_192; break; 
                case 16: oid = ASN1.STB.OID.stb34101_belt_cbc_128; break; 
                }
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(oid), new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CFB) 
            {
                // указать идентификатор алгоритма
                String oid = ASN1.STB.OID.stb34101_belt_cfb_256; switch (keyLength)
                {
                case 24: oid = ASN1.STB.OID.stb34101_belt_cfb_192; break; 
                case 16: oid = ASN1.STB.OID.stb34101_belt_cfb_128; break; 
                }
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(oid), new ASN1.OctetString(((CipherMode.CFB)mode).IV)
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CTR) 
            {
                // указать идентификатор алгоритма
                String oid = ASN1.STB.OID.stb34101_belt_ctr_256; switch (keyLength)
                {
                case 24: oid = ASN1.STB.OID.stb34101_belt_ctr_192; break; 
                case 16: oid = ASN1.STB.OID.stb34101_belt_ctr_128; break; 
                }
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(oid), new ASN1.OctetString(((CipherMode.CTR)mode).IV)
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 
            }
            // режим не поддерживается
            throw new NotSupportedException(); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Алгоритм шифрования с неизвестным заранее размером ключа
        ///////////////////////////////////////////////////////////////////////////
        private class BlockMode : CAPI.Cipher
        {
            // блочный алгоритм шифрования и режим
            private STB34101 blockCipher; private CipherMode mode; 
        
            // конструктор
            public BlockMode(STB34101 blockCipher, CipherMode mode)
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
