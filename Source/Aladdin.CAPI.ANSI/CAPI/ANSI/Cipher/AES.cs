namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования AES
    ///////////////////////////////////////////////////////////////////////////
    public class AES : BlockCipher
    {
        // конструктор
        public AES(CAPI.Factory factory, SecurityStore scope) : base(factory, scope) {}

        // тип ключа
        public override SecretKeyFactory KeyFactory 
        { 
            // тип ключа
            get { return new Keys.AES(new int[] { 16, 24, 32 }); }
        }
        // размер блока
        public override int BlockSize { get { return 16; }}

        // получить режим шифрования
        protected override CAPI.Cipher CreateBlockMode(CipherMode mode, int keyLength) 
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
                ASN1.IEncodable parameters = ASN1.Null.Instance; 

                // получить алгоритм шифрования
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, oid, parameters
                ); 
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
                ASN1.IEncodable parameters = new ASN1.OctetString(((CipherMode.CBC)mode).IV); 

                // получить алгоритм шифрования
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, oid, parameters
                ); 
                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
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
                ASN1.IEncodable parameters = new ASN1.ANSI.FBParameter(
                    new ASN1.OctetString(((CipherMode.OFB)mode).IV), new ASN1.Integer(64)
                ); 
                // получить алгоритм шифрования
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, oid, parameters
                ); 
                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CFB) 
            {
                // указать идентификатор алгоритма
                string oid = ASN1.ANSI.OID.nist_aes256_cfb; switch (keyLength)
                {
                case 24: oid = ASN1.ANSI.OID.nist_aes192_cfb; break; 
                case 16: oid = ASN1.ANSI.OID.nist_aes128_cfb; break; 
                }
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = new ASN1.ANSI.FBParameter(
                    new ASN1.OctetString(((CipherMode.CFB)mode).IV), new ASN1.Integer(64)
                ); 
                // получить алгоритм шифрования
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, oid, parameters
                ); 
                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            // вызвать базовую функцию
            return base.CreateBlockMode(mode, keyLength); 
        }
    }
}
