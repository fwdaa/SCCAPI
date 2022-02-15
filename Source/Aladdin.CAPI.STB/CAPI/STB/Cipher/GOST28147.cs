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
        // фабрика алгоритмов, область видимости и идентификатор таблицы подстановок
        private CAPI.Factory factory; private SecurityStore scope; private string sboxOID;

        // конструктор
        public GOST28147(CAPI.Factory factory, SecurityStore scope, String sboxOID)
        {
            // сохранить переданные параметры	
            this.factory = RefObject.AddRef(factory); 

            // сохранить переданные параметры	
            this.scope = RefObject.AddRef(scope); this.sboxOID = sboxOID; 
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
            // вернуть режим шифрования ECB
            if (mode is CipherMode.ECB) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_ecb), 
                    new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CFB) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_cfb), 
                    new ASN1.STB.GOSTParams(new ASN1.OctetString(((CipherMode.CFB)mode).IV), 
                        new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
                    )
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
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
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_ctr), 
                    new ASN1.STB.GOSTParams(new ASN1.OctetString(((CipherMode.CTR)mode).IV), 
                        new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
                    )
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
            
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
