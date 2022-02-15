using System;

namespace Aladdin.CAPI.STB.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент управления выбора параметров ключа ГОСТ 
    ///////////////////////////////////////////////////////////////////////////
    public partial class KeyControl11762S : CAPI.GUI.ParametersControl
    {
        // конструктор
        public KeyControl11762S() { InitializeComponent(); }

		// получить параметры ключа
        public override IParameters GetParameters()
        {
            // указать идентификатор ключа
            string keyOID = ASN1.STB.OID.stb11762_bds_pubKey; string oid = null; 

            // указать фабрику кодирования
            KeyFactory keyFactory = new STB11762.BDSKeyFactory(keyOID); 

            // указать идентификатор параметров
            if (radio3 .Checked) oid = ASN1.STB.OID.stb11762_params3_bds;  else 
            if (radio6 .Checked) oid = ASN1.STB.OID.stb11762_params6_bds;  else 
            if (radio10.Checked) oid = ASN1.STB.OID.stb11762_params10_bds; 

            // закодировать идентификатор параметров
            ASN1.ObjectIdentifier paramOID = new ASN1.ObjectIdentifier(oid); 
                
		    // закодировать параметры ключа
            ASN1.IEncodable encoded = ASN1.Explicit.Encode(ASN1.Tag.Context(0), paramOID); 

            // раскодировать параметры ключа
            return keyFactory.DecodeParameters(encoded);
        }
    }
}
