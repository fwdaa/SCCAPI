using System;

namespace Aladdin.CAPI.GOST.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент управления выбора параметров ключа ГОСТ 
    ///////////////////////////////////////////////////////////////////////////
    public partial class KeyControl1994S : CAPI.GUI.ParametersControl
    {
        // конструктор
        public KeyControl1994S() { InitializeComponent(); }

		// получить параметры ключа
        public override IParameters GetParameters()
        {
            // выбранные параметры
            String paramsOID = null; String hashOID = null; String encryptionOID = null;

            // указать фабрику кодирования ключей
            KeyFactory keyFactory = new GOSTR3410.DHKeyFactory(
                ASN1.GOST.OID.gostR3410_1994
            ); 
            // указать идентификатор набора параметров кривых
            if (radioECA.Checked) paramsOID = ASN1.GOST.OID.signs_A; else
            if (radioECB.Checked) paramsOID = ASN1.GOST.OID.signs_B; else
            if (radioECC.Checked) paramsOID = ASN1.GOST.OID.signs_C; else
            if (radioECD.Checked) paramsOID = ASN1.GOST.OID.signs_D; 

            // указать идентификатор параметров хэширования
            if (radioHashT .Checked) hashOID = ASN1.GOST.OID.hashes_test; else
            if (radioHashCP.Checked) hashOID = ASN1.GOST.OID.hashes_cryptopro;
                
            // указать идентификатор параметров шифрования
            if (radioA.Checked) encryptionOID = ASN1.GOST.OID.encrypts_A; else
            if (radioB.Checked) encryptionOID = ASN1.GOST.OID.encrypts_B; else
            if (radioC.Checked) encryptionOID = ASN1.GOST.OID.encrypts_C; else
            if (radioD.Checked) encryptionOID = ASN1.GOST.OID.encrypts_D; 

            // закодировать параметры кривых
	        ASN1.ObjectIdentifier encodedParamOID = new ASN1.ObjectIdentifier(paramsOID); 
                
            // закодировать параметры хэширования
	        ASN1.ObjectIdentifier encodedHashOID = new ASN1.ObjectIdentifier(hashOID); 

	        // закодировать параметры шифрования
	        ASN1.ObjectIdentifier encodedEncryptionOID = new ASN1.ObjectIdentifier(encryptionOID); 

            // закодировать все параметры
            ASN1.IEncodable encoded = new ASN1.GOST.GOSTR3410PublicKeyParameters2001(
                encodedParamOID, encodedHashOID, encodedEncryptionOID
            ); 
            // раскодировать параметры
            return keyFactory.DecodeParameters(encoded); 
        }
    }
}
