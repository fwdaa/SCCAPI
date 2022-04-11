namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования DES
    ///////////////////////////////////////////////////////////////////////////
    public class DES : BlockCipher
    {
        // конструктор
        public DES(CAPI.Factory factory, SecurityStore scope) : base(factory, scope) {}

        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.DES.Instance; }}
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
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, ASN1.ANSI.OID.ssig_des_ecb, parameters
                ); 
                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            // в зависимости от режима
            if (mode is CipherMode.CBC) 
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = new ASN1.OctetString(((CipherMode.CBC)mode).IV); 

                // получить алгоритм шифрования
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, ASN1.ANSI.OID.ssig_des_cbc, parameters
                ); 
                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            // в зависимости от режима
            if (mode is CipherMode.OFB) 
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = new ASN1.ANSI.FBParameter(
                    new ASN1.OctetString(((CipherMode.OFB)mode).IV), new ASN1.Integer(64)
                ); 
                // получить алгоритм шифрования
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, ASN1.ANSI.OID.ssig_des_ofb, parameters
                ); 
                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            // в зависимости от режима
            if (mode is CipherMode.CFB) 
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = new ASN1.ANSI.FBParameter(
                    new ASN1.OctetString(((CipherMode.CFB)mode).IV), new ASN1.Integer(64)
                ); 
                // получить алгоритм шифрования
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, ASN1.ANSI.OID.ssig_des_cfb, parameters
                ); 
                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            // вызвать базовую функцию
            return CreateBlockMode(mode, 8); 
        }
    }
}