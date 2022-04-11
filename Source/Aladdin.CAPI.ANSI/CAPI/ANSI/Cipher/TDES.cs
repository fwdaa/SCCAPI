namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования TDES
    ///////////////////////////////////////////////////////////////////////////
    public class TDES : BlockCipher
    {
        // конструктор
        public TDES(CAPI.Factory factory, SecurityStore scope) : base(factory, scope) {}

        // тип ключа
        public override SecretKeyFactory KeyFactory 
        { 
            // тип ключа
            get { return new Keys.TDES(new int[] { 16, 24 }); }
        }
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
                    Scope, ASN1.ANSI.OID.ssig_tdes_ecb, parameters
                ); 
                // проверить наличие алгоритма
                if (cipher != null) return cipher; 
            }
            // вызвать базовую функцию
            return CreateBlockMode(mode, 0); 
        }
    }
}