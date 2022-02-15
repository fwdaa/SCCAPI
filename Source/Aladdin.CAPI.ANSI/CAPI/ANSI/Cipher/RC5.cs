using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования RC5
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class RC5 : RefObject, IBlockCipher
    {
        // фабрика алгоритмов и область видимости
        private CAPI.Factory factory; private SecurityStore scope; 
        // размер блока и число раундов
        private int blockSize; private int rounds; 

        // конструктор
        public RC5(CAPI.Factory factory, SecurityStore scope, int blockSize, int rounds)
        {
            // сохранить переданные параметры	
            this.factory = RefObject.AddRef(factory); 

            // сохранить переданные параметры	
            this.scope = RefObject.AddRef(scope); 
            
            // сохранить переданные параметры	
            this.blockSize = blockSize; this.rounds = rounds; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); RefObject.Release(factory); base.OnDispose();
        }
        // тип ключа
        public SecretKeyFactory KeyFactory  { get { return Keys.RC5.Instance; }}
        // размер ключей
        public int[] KeySizes { get { return CAPI.KeySizes.Range(1, 256); }} 
        // размер блока
        public int BlockSize { get { return blockSize; }}

        // получить режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode)
        {
            // в зависимости от режима
            if (mode is CipherMode.CBC) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc5_cbc), 
                    new ASN1.ANSI.RSA.RC5CBCParameter(
                        new ASN1.Integer(16), new ASN1.Integer(rounds), 
                        new ASN1.Integer(blockSize * 8), 
                        new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                    )
                );
                // получить алгоритм шифрования
                using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                    scope, parameters))
                {
                    // изменить режим дополнения
                    return new BlockMode.ConvertPadding(cipher, PaddingMode.Any); 
                }
            }
            // режим не поддерживается
            throw new NotSupportedException();
        }
    }
}
