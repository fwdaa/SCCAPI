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
        private CAPI.Factory factory; private SecurityStore scope; private int keyLength;

        // конструктор
        public STB34101(CAPI.Factory factory, SecurityStore scope, int keyLength)
        {
            // сохранить переданные параметры	
            this.factory = RefObject.AddRef(factory); 

            // сохранить переданные параметры	
            this.scope = RefObject.AddRef(scope); this.keyLength = keyLength; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); RefObject.Release(factory); base.OnDispose();
        }
        // тип ключа
        public SecretKeyFactory KeyFactory { get { return Keys.STB34101.Instance; }}
        // размер ключей
        public int[] KeySizes { get { return new int[] {keyLength}; }} 
        // размер блока
        public int BlockSize { get { return 16; }} 
        
        // получить режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode)
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
    }
}
