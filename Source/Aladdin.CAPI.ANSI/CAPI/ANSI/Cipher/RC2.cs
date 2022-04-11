namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования RC2
    ///////////////////////////////////////////////////////////////////////////
    public class RC2 : BlockCipher
    {
        // эффективное число битов 
        private int effectiveKeyBits; 
        
        // конструктор
        public RC2(CAPI.Factory factory, SecurityStore scope, int effectiveKeyBits)

            // сохранить переданные параметры
            : base(factory, scope) { this.effectiveKeyBits = effectiveKeyBits; }

        // тип ключа
        public override SecretKeyFactory KeyFactory  
        { 
            // тип ключа
            get { return new Keys.RC2(CAPI.KeySizes.Range(1, 128)); }
        }
        // размер блока
        public override int BlockSize { get { return 8; }} 
        
        // получить режим шифрования
        public override CAPI.Cipher CreateBlockMode(CipherMode mode)
        {
            // закодировать эффективное число битов
            ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.
                GetVersion(effectiveKeyBits); 

            // в зависимости от режима
            if (mode is CipherMode.ECB) 
            {
                // получить алгоритм шифрования
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, ASN1.ANSI.OID.rsa_rc2_ecb, version
                ); 
                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            if (mode is CipherMode.CBC) 
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = new ASN1.ANSI.RSA.RC2CBCParams(
                    version, new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                ); 
                // получить алгоритм шифрования
                CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, ASN1.ANSI.OID.rsa_rc2_cbc, parameters
                ); 
                // вернуть алгоритм шифрования
                if (cipher != null) return cipher; 
            }
            // вызвать базовую функцию
            return CreateBlockMode(mode, 0); 
        }
    }
}