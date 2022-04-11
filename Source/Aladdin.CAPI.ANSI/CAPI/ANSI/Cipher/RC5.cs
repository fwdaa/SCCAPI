namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования RC5
    ///////////////////////////////////////////////////////////////////////////
    public class RC5 : BlockCipher
    {
        // размер блока и число раундов
        private int blockSize; private int rounds; 

        // конструктор
        public RC5(CAPI.Factory factory, SecurityStore scope, int blockSize, int rounds)

            // сохранить переданные параметры	
            : base(factory, scope) { this.blockSize = blockSize; this.rounds = rounds; }

        // тип ключа
        public override SecretKeyFactory KeyFactory  
        { 
            // тип ключа
            get { return new Keys.RC5(CAPI.KeySizes.Range(1, 256)); }
        }
        // размер блока
        public override int BlockSize { get { return blockSize; }}

        // получить режим шифрования
        public override CAPI.Cipher CreateBlockMode(CipherMode mode)
        {
            // в зависимости от режима
            if (mode is CipherMode.CBC) 
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable parameters = new ASN1.ANSI.RSA.RC5CBCParameter(
                    new ASN1.Integer(16), new ASN1.Integer(rounds), 
                    new ASN1.Integer(blockSize * 8), 
                    new ASN1.OctetString(((CipherMode.CBC)mode).IV)
                ); 
                // получить алгоритм шифрования
                using (CAPI.Cipher cipher = Factory.CreateAlgorithm<CAPI.Cipher>(
                    Scope, ASN1.ANSI.OID.rsa_rc5_cbc, parameters))
                {
                    // изменить режим дополнения
                    return new BlockMode.PaddingConverter(cipher, PaddingMode.Any); 
                }
            }
            // вызвать базовую функцию
            return CreateBlockMode(mode, 0); 
        }
    }
}
