using System;

namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования DES-X
    ///////////////////////////////////////////////////////////////////////////
    public class DESX : BlockCipher
    {
        // конструктор
        public DESX(CAPI.Factory factory, SecurityStore scope) : base(factory, scope) {}

        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.DESX.Instance; }}
        // размер блока
        public override int BlockSize { get { return 8; }}

        // получить режим шифрования
        public override CAPI.Cipher CreateBlockMode(CipherMode mode)
        {
            // в зависимости от режима
            if (mode is CipherMode.ECB) 
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = ASN1.Null.Instance; 

                // получить алгоритм шифрования
                using (CAPI.Cipher engine = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, ASN1.ANSI.OID.ssig_des_ecb, parameters)) 
                {
                    // вернуть алгоритм шифрования
                    if (engine == null) throw new NotSupportedException();
                
                    // создать модификацию алгоритма
                    using (CAPI.Cipher desX = new Engine.DESX(engine))
                    {
                        // вернуть режим алгоритма
                        return new BlockMode.PaddingConverter(desX, PaddingMode.Any); 
                    }
                }
            }
            // в зависимости от режима
            if (mode is CipherMode.CBC) 
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = new ASN1.OctetString(((CipherMode.CBC)mode).IV); 

                // получить алгоритм шифрования
                using (CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, ASN1.ANSI.OID.rsa_desx_cbc, parameters))
                {
                    // проверить наличие алгоритма
                    if (cipher != null) return cipher; 
                }
            }
            // вызвать базовую функцию
            return CreateBlockMode(mode, 24); 
        }
    }
}
