using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.KZ.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // ГОСТ 28147-89
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class GOST28147 : RefObject, IBlockCipher
    {
        // фабрика алгоритмов и область видимости
        private CAPI.Factory factory; private SecurityStore scope; 

        // конструктор
        public GOST28147(CAPI.Factory factory, SecurityStore scope) 
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
        public SecretKeyFactory KeyFactory { get { return GOST.Keys.GOST28147.Instance; }}
        // размер ключей
        public int[] KeySizes { get { return new int[] {32}; }}
        // размер блока
        public int BlockSize { get { return 8; }}
    
        // получить режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode) 
        {
            // в зависимости от режима
            if (mode is CipherMode.ECB) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_ecb), ASN1.Null.Instance
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CBC) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_cbc), 
                    new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new Mode.CBC(engine, (CipherMode.CBC)mode, PaddingMode.Any); 
                }
            }
            if (mode is CipherMode.CFB) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_cfb), 
                    new ASN1.OctetString(((CipherMode.CFB)mode).IV)
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new Mode.CFB(engine, (CipherMode.CFB)mode); 
                }
            }
            if (mode is CipherMode.OFB) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_ofb), 
                    new ASN1.OctetString(((CipherMode.OFB)mode).IV)
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new Mode.OFB(engine, (CipherMode.OFB)mode); 
                }
            }
            if (mode is CipherMode.CTR) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_cnt), 
                    new ASN1.OctetString(((CipherMode.CTR)mode).IV)
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new Mode.CTR(engine, (CipherMode.CTR)mode); 
                }
            }
            // режим не поддерживается
            throw new NotSupportedException(); 
        }
    }
}
