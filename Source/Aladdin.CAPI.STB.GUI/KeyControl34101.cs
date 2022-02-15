using System;

namespace Aladdin.CAPI.STB.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент управления выбора параметров ключа ГОСТ 
    ///////////////////////////////////////////////////////////////////////////
    public partial class KeyControl34101 : CAPI.GUI.ParametersControl
    {
        // конструктор
        public KeyControl34101() { InitializeComponent(); }

		// получить параметры ключа
        public override IParameters GetParameters()
        {
            // указать идентификатор ключа
            string keyOID = ASN1.STB.OID.stb34101_bign_pubKey; string oid = null; 

            // указать фабрику кодирования
            KeyFactory keyFactory = new STB34101.KeyFactory(keyOID);

            // указать идентификатор параметров
            if (radio256.Checked) oid = ASN1.STB.OID.stb34101_bign_curve256_v1; else 
            if (radio384.Checked) oid = ASN1.STB.OID.stb34101_bign_curve384_v1; else 
            if (radio512.Checked) oid = ASN1.STB.OID.stb34101_bign_curve512_v1; 

	        // закодировать параметры ключа
            ASN1.IEncodable encoded = new ASN1.ObjectIdentifier(oid); 

            // раскодировать параметры ключа
            return keyFactory.DecodeParameters(encoded);
        }
    }
}
