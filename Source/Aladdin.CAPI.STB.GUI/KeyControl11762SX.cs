using System;

namespace Aladdin.CAPI.STB.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент управления выбора параметров ключа ГОСТ 
    ///////////////////////////////////////////////////////////////////////////
    public partial class KeyControl11762SX : CAPI.GUI.ParametersControl
    {
        // конструктор
        public KeyControl11762SX() { InitializeComponent(); }

		// получить параметры ключа
        public override IParameters GetParameters()
        {
            // указать идентификатор ключа
            string keyOID = ASN1.STB.OID.stb11762_bdsbdh_pubKey; string oid = null; 

            // указать фабрику кодирования
            KeyFactory keyFactory = new STB11762.BDSBDHKeyFactory(keyOID); 

            // указать идентификатор параметров
            if (radio3 .Checked) oid = ASN1.STB.OID.stb11762_params3;  else 
            if (radio6 .Checked) oid = ASN1.STB.OID.stb11762_params6;  else 
            if (radio10.Checked) oid = ASN1.STB.OID.stb11762_params10; 

            // закодировать идентификатор параметров
            ASN1.ObjectIdentifier paramOID = new ASN1.ObjectIdentifier(oid); 
                
		    // закодировать параметры ключа
            ASN1.IEncodable encoded = ASN1.Explicit.Encode(ASN1.Tag.Context(2), paramOID); 

            // раскодировать параметры ключа
            return keyFactory.DecodeParameters(encoded);
        }
    }
}
