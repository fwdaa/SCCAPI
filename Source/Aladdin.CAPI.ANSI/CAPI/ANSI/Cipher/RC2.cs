using System; 
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования RC2
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class RC2 : RefObject, IBlockCipher
    {
        // фабрика алгоритмов и область видимости
        private CAPI.Factory factory; private SecurityStore scope; 
        // эффективное число битов и размер ключа
        private int effectiveKeyBits; private int keyLength; 
        
        // конструктор
        public RC2(CAPI.Factory factory, SecurityStore scope, 
            int effectiveKeyBits, int keyLength)
        {
            // сохранить переданные параметры	
            this.factory = RefObject.AddRef(factory); 

            // указать число битов по умолчанию
            this.scope = RefObject.AddRef(scope); 

            // сохранить переданные параметры
            this.effectiveKeyBits = effectiveKeyBits; this.keyLength = keyLength; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); RefObject.Release(factory); base.OnDispose();
        }
        // тип ключа
        public CAPI.SecretKeyFactory KeyFactory  { get { return Keys.RC2.Instance; }}
        // размер ключей 
        public int[] KeySizes { get { return new int[] {keyLength}; }} 
        // размер блока
        public int BlockSize { get { return 8; }} 
        
        // получить режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode)
        {
            // закодировать эффективное число битов
            ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(effectiveKeyBits); 

            // в зависимости от режима
            if (mode is CipherMode.ECB) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_ecb), version
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 

                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CBC) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_cbc), 
                    new ASN1.ANSI.RSA.RC2CBCParams(
                        version, new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                    )
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 

                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            // режим не поддерживается
            throw new NotSupportedException();
        }
    }
}