using System;
using System.Collections.Generic;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей ГОСТ R 34.10-2001, 2012
	///////////////////////////////////////////////////////////////////////////
	public class KeyPairGenerator : CAPI.PKCS11.KeyPairGenerator
	{
		// параметры генерации
		private GOST.GOSTR3410.INamedParameters parameters; 

		// конструктор
		public KeyPairGenerator(CAPI.PKCS11.Applet applet, SecurityObject scope, 
			IRand rand, GOST.GOSTR3410.INamedParameters parameters)

			// сохранить переданные параметры
			: base(applet, scope, rand) { this.parameters = parameters; }

		// сгенерировать пару ключей
		public override KeyPair Generate(string keyOID, KeyUsage keyUsage)
        {
	        // указать программный алгоритм генерации
	        using (CAPI.KeyPairGenerator generator = new CAPI.GOST.GOSTR3410.ECKeyPairGenerator(
			    Factory, Scope, Rand, (CAPI.GOST.GOSTR3410.IECParameters)parameters))
            {
	            // сгенерировать пару ключей
	            return generator.Generate(null, keyOID, keyUsage, KeyFlags.None);  
            }
        }
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session sesssion, string keyOID)
		{
			// в зависимости от идентификатора ключа
			if (keyOID != ASN1.GOST.OID.gostR3410_2012_512)
			{
				// вернуть параметры алгоритма
				return new Mechanism(API.CKM_GOSTR3410_KEY_PAIR_GEN); 
			}
			// вернуть параметры алгоритма
			else return new Mechanism(API.CKM_GOSTR3410_512_KEY_PAIR_GEN); 
		}
		// атрибуты открытого ключа
		protected override CAPI.PKCS11.Attribute[] GetPublicAttributes(string keyOID)
        {
	        // создать список атрибутов
	        List<CAPI.PKCS11.Attribute> attributes = new List<CAPI.PKCS11.Attribute>(); 

	        // указать идентификатор набора
	        attributes.Add(Applet.Provider.CreateAttribute(
                API.CKA_GOSTR3410_PARAMS, 
		        new ASN1.ObjectIdentifier(parameters.ParamOID).Encoded
	        ));   
	        // в зависимости от идентификатора ключа
	        if (keyOID != ASN1.GOST.OID.gostR3410_2012_512)
	        {
		        // указать идентификатор набора
		        attributes.Add(Applet.Provider.CreateAttribute(
                    API.CKA_GOSTR3411_PARAMS, 
			        new ASN1.ObjectIdentifier(parameters.HashOID).Encoded
		        ));   
		        // указать идентификатор набора
		        attributes.Add(Applet.Provider.CreateAttribute(
		            API.CKA_GOST28147_PARAMS, 
			        new ASN1.ObjectIdentifier(parameters.SBoxOID).Encoded
		        ));   
	        }
	        // создать список атрибутов
	        return attributes.ToArray();  
        }
	}
}
