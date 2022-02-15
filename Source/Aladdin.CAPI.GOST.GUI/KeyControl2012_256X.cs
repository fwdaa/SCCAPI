using System;

namespace Aladdin.CAPI.GOST.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент управления выбора параметров ключа ГОСТ 
    ///////////////////////////////////////////////////////////////////////////
    public partial class KeyControl2012_256X : CAPI.GUI.ParametersControl
    {
        // конструктор
        public KeyControl2012_256X() { InitializeComponent(); }

		// получить параметры ключа
        public override IParameters GetParameters()
        {
            // выбранные параметры
            String paramsOID = null; String hashOID = null; 

            // указать фабрику кодирования ключей
            KeyFactory keyFactory = new GOSTR3410.ECKeyFactory(
                ASN1.GOST.OID.gostR3410_2012_256
            ); 
            // указать идентификатор набора параметров кривых
            if (radioECA    .Checked) paramsOID = ASN1.GOST.OID.ecc_exchanges_A; else
            if (radioECB    .Checked) paramsOID = ASN1.GOST.OID.ecc_exchanges_B; else 
            if (radioECTC026.Checked) paramsOID = ASN1.GOST.OID.ecc_tc26_2012_256A;

            // указать идентификатор параметров хэширования
            hashOID = ASN1.GOST.OID.gostR3411_2012_256; 
                
            // закодировать параметры кривых
	        ASN1.ObjectIdentifier encodedParamOID = new ASN1.ObjectIdentifier(paramsOID); 
                
            // закодировать параметры хэширования
	        ASN1.ObjectIdentifier encodedHashOID = new ASN1.ObjectIdentifier(hashOID); 

            // закодировать все параметры
            ASN1.IEncodable encoded = new ASN1.GOST.GOSTR3410PublicKeyParameters2012(
                encodedParamOID, encodedHashOID
            ); 
            // раскодировать параметры
            return keyFactory.DecodeParameters(encoded); 
        }
    }
}
