using System;

namespace Aladdin.CAPI.GOST.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент управления выбора параметров ключа ГОСТ 
    ///////////////////////////////////////////////////////////////////////////
    public partial class KeyControl2012_512 : CAPI.GUI.ParametersControl
    {
        // конструктор
        public KeyControl2012_512() { InitializeComponent(); }

		// получить параметры ключа
        public override IParameters GetParameters()
        {
            // выбранные параметры
            String paramsOID = null; String hashOID = null; 

            // указать фабрику кодирования ключей
            KeyFactory keyFactory = new GOSTR3410.ECKeyFactory(
                ASN1.GOST.OID.gostR3410_2012_512
            ); 
            // указать идентификатор набора параметров кривых
            if (radioECA.Checked) paramsOID = ASN1.GOST.OID.ecc_tc26_2012_512A; else
            if (radioECB.Checked) paramsOID = ASN1.GOST.OID.ecc_tc26_2012_512B; else
            if (radioECC.Checked) paramsOID = ASN1.GOST.OID.ecc_tc26_2012_512C; 

            // указать идентификатор параметров хэширования
            hashOID = ASN1.GOST.OID.gostR3411_2012_512; 
                
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
