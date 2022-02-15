using System; 
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования TDES
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class TDES : RefObject, IBlockCipher
    {
        // фабрика алгоритмов, область видимости и размер ключа
        private CAPI.Factory factory; private SecurityStore scope; private int keyLength; 

        // конструктор
        public TDES(CAPI.Factory factory, SecurityStore scope, int keyLength)
        {
            // сохранить переданные параметры	
            this.factory = RefObject.AddRef(factory); 
            this.scope   = RefObject.AddRef(scope  ); this.keyLength = keyLength; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); RefObject.Release(factory); base.OnDispose();
        }
        // тип ключа
        public SecretKeyFactory KeyFactory { get { return Keys.TDES.Instance; }}
        // размер ключей
        public int[] KeySizes { get { return new int[] {keyLength}; }}
        // размер блока
        public int BlockSize { get { return 8; }}

        // получить режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode) 
        {
            if (keyLength == 24 && mode is CipherMode.ECB)
            { 
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_tdes192_ecb), ASN1.Null.Instance
                );
                // получить алгоритм шифрования
                using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                { 
                    // изменить режим дополнения
                    if (cipher != null) return new BlockMode.ConvertPadding(cipher, PaddingMode.Any); 
                }
            }
            if (keyLength == 24 && mode is CipherMode.CBC)
            { 
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_tdes192_cbc), 
                    new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                );
                // получить алгоритм шифрования
                using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                { 
                    // изменить режим дополнения
                    if (cipher != null) return new BlockMode.ConvertPadding(cipher, PaddingMode.Any); 
                }
            }
            // в зависимости от режима
            if (mode is CipherMode.ECB)
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_tdes_ecb), ASN1.Null.Instance
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 

                // проверить наличие алгоритма
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CBC) 
            {
                // получить алгоритм шифрования блока
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB()))
                {
                    // вернуть режим шифрования
                    return new Mode.CBC(engine, (CipherMode.CBC)mode, PaddingMode.Any); 
                }
            }
            // в зависимости от режима
            if (mode is CipherMode.OFB) 
            {
                // получить алгоритм шифрования
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB())) 
                {
                    // вернуть режим шифрования
                    return new Mode.OFB(engine, (CipherMode.OFB)mode); 
                }
            }
            // в зависимости от режима
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
    }
}