using System; 
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования AES
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class AES : RefObject, IBlockCipher
    {
        // фабрика алгоритмов и область видимости
        private CAPI.Factory factory; private SecurityStore scope; private int keyLength; 

        // конструктор
        public AES(CAPI.Factory factory, SecurityStore scope, int keyLength)
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
        public SecretKeyFactory KeyFactory { get { return Keys.AES.Instance; }}
        // размер ключей
        public int[] KeySizes { get { return new int[] {keyLength}; }}
        // размер блока
        public int BlockSize { get { return 16; }}

        // получить режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode) 
        {
            // в зависимости от режима
            if (mode is CipherMode.ECB) 
            {
                // указать идентификатор алгоритма
                string oid = ASN1.ANSI.OID.nist_aes256_ecb; switch (keyLength)
                {
                case 24: oid = ASN1.ANSI.OID.nist_aes192_ecb; break; 
                case 16: oid = ASN1.ANSI.OID.nist_aes128_ecb; break; 
                }
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 

                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CBC) 
            {
                // указать идентификатор алгоритма
                string oid = ASN1.ANSI.OID.nist_aes256_cbc; switch (keyLength)
                {
                case 24: oid = ASN1.ANSI.OID.nist_aes192_cbc; break; 
                case 16: oid = ASN1.ANSI.OID.nist_aes128_cbc; break; 
                }
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(oid), 
                    new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 

                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования блока
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB()))
                {
                    // вернуть режим шифрования
                    return new Mode.CBC(engine, (CipherMode.CBC)mode, PaddingMode.Any); 
                }
            }
            if (mode is CipherMode.OFB) 
            {
                // указать идентификатор алгоритма
                string oid = ASN1.ANSI.OID.nist_aes256_ofb; switch (keyLength)
                {
                case 24: oid = ASN1.ANSI.OID.nist_aes192_ofb; break; 
                case 16: oid = ASN1.ANSI.OID.nist_aes128_ofb; break; 
                }
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(oid), new ASN1.ANSI.FBParameter(
                        new ASN1.OctetString(((CipherMode.OFB)mode).IV), new ASN1.Integer(64)
                    )
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 

                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования блока
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB()))
                {
                    // вернуть режим шифрования
                    return new Mode.OFB(engine, (CipherMode.OFB)mode); 
                }
            }
            if (mode is CipherMode.CFB) 
            {
                // указать идентификатор алгоритма
                String oid = ASN1.ANSI.OID.nist_aes256_cfb; switch (keyLength)
                {
                case 24: oid = ASN1.ANSI.OID.nist_aes192_cfb; break; 
                case 16: oid = ASN1.ANSI.OID.nist_aes128_cfb; break; 
                }
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(oid), new ASN1.ANSI.FBParameter(
                        new ASN1.OctetString(((CipherMode.CFB)mode).IV), new ASN1.Integer(64)
                    )
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 

                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования блока
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB()))
                {
                    // вернуть режим шифрования
                    return new Mode.CFB(engine, (CipherMode.CFB)mode); 
                }
            }
            // режим не поддерживается
            throw new NotSupportedException();
        }
    }
}