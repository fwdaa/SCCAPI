using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.STB.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // ГОСТ 28147-89
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class GOST28147 : RefObject, IBlockCipher
    {
        // фабрика алгоритмов и область видимости 
        private CAPI.Factory factory; private SecurityStore scope; 
        // таблица подстановок
        private ASN1.STB.GOSTSBlock sbox;

        // конструктор
        public GOST28147(CAPI.Factory factory, SecurityStore scope, ASN1.STB.GOSTSBlock sbox)
        {
            // сохранить переданные параметры	
            this.factory = RefObject.AddRef(factory); 

            // сохранить переданные параметры	
            this.scope = RefObject.AddRef(scope); this.sbox = sbox; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); RefObject.Release(factory); base.OnDispose();
        }
        // тип ключа
        public SecretKeyFactory KeyFactory { get { return GOST.Keys.GOST.Instance; }}
        // размер блока
        public int BlockSize { get { return 8; }}
    
        // получить режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode)
        {
            // вернуть режим шифрования ECB
            if (mode is CipherMode.ECB) 
            {
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                    scope, ASN1.STB.OID.gost28147_ecb, sbox
                ); 
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CFB) 
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = new ASN1.STB.GOSTParams(
                    new ASN1.OctetString(((CipherMode.CFB)mode).IV), sbox
                ); 
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                    scope, ASN1.STB.OID.gost28147_cfb, parameters
                ); 
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new GOST.Mode.GOST28147.CFB(engine, (CipherMode.CFB)mode); 
                }
            }
            if (mode is CipherMode.CTR) 
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = new ASN1.STB.GOSTParams(
                    new ASN1.OctetString(((CipherMode.CTR)mode).IV), sbox
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                    scope, ASN1.STB.OID.gost28147_ctr, parameters
                ); 
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new GOST.Mode.GOST28147.CTR(engine, (CipherMode.CTR)mode); 
                }
            }
            // режим не поддерживается
            throw new NotSupportedException(); 
        }
    }
}
