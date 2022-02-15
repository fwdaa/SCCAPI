using System;

namespace Aladdin.CAPI.ANSI.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент управления выбора параметров ключа ECDSA/ECDH
    ///////////////////////////////////////////////////////////////////////////
    public partial class ECControl : CAPI.GUI.ParametersControl
    {
        // конструктор
        public ECControl() { InitializeComponent(); }

		// получить параметры ключа
        public override IParameters GetParameters() 
        { 
            // указать идентификатор ключа
            string keyOID = ASN1.ANSI.OID.x962_ec_public_key; string oid = null; 
         
            // указать фабрику кодирования
            KeyFactory keyFactory = new X962.KeyFactory(keyOID); 

            // указать идентификатор ключа
            if (radio256.Checked) oid = ASN1.ANSI.OID.x962_curves_prime256v1   ; else 
            if (radio384.Checked) oid = ASN1.ANSI.OID.certicom_curves_secp384r1; else
            if (radio521.Checked) oid = ASN1.ANSI.OID.certicom_curves_secp521r1; 

            // раскодировать параметры ключа
            return keyFactory.DecodeParameters(new ASN1.ObjectIdentifier(oid)); 
        } 
    }
}
