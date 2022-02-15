using System; 
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования DES
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class DES : RefObject, IBlockCipher
    {
        // фабрика алгоритмов и область видимости
        private CAPI.Factory factory; private SecurityStore scope; 

        // конструктор
        public DES(CAPI.Factory factory, SecurityStore scope) 
        {
            // сохранить переданные параметры	
            this.factory = RefObject.AddRef(factory); this.scope = RefObject.AddRef(scope);
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); RefObject.Release(factory); base.OnDispose();
        }
        // тип ключа
        public SecretKeyFactory KeyFactory { get { return Keys.DES.Instance; }}
        // размер ключей
        public int[] KeySizes { get { return new int[] {8}; }}
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
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 

                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            // в зависимости от режима
            if (mode is CipherMode.CBC) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_cbc), 
                    new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                );
                // получить алгоритм шифрования
                CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 

                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 

                // получить алгоритм шифрования блока
                using (CAPI.Cipher engine = CreateBlockMode(new CipherMode.ECB()))
                {
                    // вернуть режим алгоритма
                    return new Mode.CBC(engine, (CipherMode.CBC)mode, PaddingMode.Any); 
                }
            }
            // в зависимости от режима
            if (mode is CipherMode.OFB) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ofb), 
                    new ASN1.ANSI.FBParameter(
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
                    // вернуть режим алгоритма
                    return new Mode.OFB(engine, (CipherMode.OFB)mode); 
                }
            }
            // в зависимости от режима
            if (mode is CipherMode.CFB) 
            {
                // закодировать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ofb), 
                    new ASN1.ANSI.FBParameter(
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
                    // вернуть режим алгоритма
                    return new Mode.CFB(engine, (CipherMode.CFB)mode); 
                }
            }
            // режим не поддерживается
            throw new NotSupportedException();
        }
        ///////////////////////////////////////////////////////////////////////////
        // Нормализация ключа DES
        ///////////////////////////////////////////////////////////////////////////
        public static void AdjustKeyParity(byte[] key, int offset, int length)
        {
            // для всех байтов ключа
            for (int i = 0; i < length; i++)
            {
                // для вех битов
                int ones = 0; for (int j = 0; j < 8; j++)
                {
                    // определить число установленных битов
                    if ((key[i + offset] & (0x1 << j)) != 0) ones++;
                }
                // число установленных битов должно быть нечетным
                if((ones % 2) == 0) key[i + offset] ^= 0x01;
            }
        } 
    }
}