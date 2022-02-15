using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования DES-X
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class DESX : RefObject, IBlockCipher
    {
        // фабрика алгоритмов и область видимости
        private CAPI.Factory factory; private SecurityStore scope; 

        // конструктор
        public DESX(CAPI.Factory factory, SecurityStore scope)
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
        public SecretKeyFactory KeyFactory { get { return Keys.DESX.Instance; }}
        // размер ключей
        public int[] KeySizes { get { return new int[] {24}; }} 
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
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                );
                // получить алгоритм шифрования
                using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters)) 
                {
                    // вернуть алгоритм шифрования
                    if (engine == null) throw new NotSupportedException();
                
                    // создать модификацию алгоритма
                    using (CAPI.Cipher desX = new Engine.DESX(engine))
                    {
                        // вернуть режим алгоритма
                        return new BlockMode.ConvertPadding(desX, PaddingMode.Any); 
                    }
                }
            }
            // в зависимости от режима
            if (mode is CipherMode.CBC) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_desx_cbc), 
                    new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                );
                // получить алгоритм шифрования
                using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                    scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (cipher != null) return cipher; 
                }
                // получить алгоритм шифрования
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
