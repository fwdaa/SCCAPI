using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.X962
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм генерации ключей EC/ECDSA
    ///////////////////////////////////////////////////////////////////////////
    public class KeyPairGenerator : CAPI.PKCS11.KeyPairGenerator
    {
	    // параметры генерации и информация алгоритма
	    private ANSI.X962.IParameters parameters; private MechanismInfo info;

	    // конструктор
	    public KeyPairGenerator(CAPI.PKCS11.Applet applet, SecurityObject scope, 
            IRand rand, ANSI.X962.IParameters parameters) : base(applet, scope, rand)
	    {
		    // сохранить переданные параметры
		    this.parameters = parameters; 
            
            // получить информацию алгоритма
            info = Applet.GetAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN);
        }
	    // сгенерировать пару ключей
	    public override KeyPair Generate(string keyOID, KeyUsage keyUsage) 
        {
            // указать программный алгоритм генерации
            using (CAPI.KeyPairGenerator generator = new ANSI.X962.KeyPairGenerator(
                Factory, Scope, Rand, parameters))
            { 
                // сгенерировать пару ключей
                return generator.Generate(null, keyOID, keyUsage, KeyFlags.None);  
            }
        }
	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, string keyOID)
	    {
		    // вернуть параметры алгоритма
		    return new Mechanism(API.CKM_EC_KEY_PAIR_GEN); 
	    }
	    // атрибуты открытого ключа
        protected override CAPI.PKCS11.Attribute[] GetPublicAttributes(string keyOID)
        { 
            // создать атрибут параметров
            CAPI.PKCS11.Attribute parametersAttribute = 
                PublicKey.GetParametersAttribute(
                    (CAPI.PKCS11.Provider)Factory, parameters, info.Flags
            ); 
            // вернуть атрибут параметров
            return new CAPI.PKCS11.Attribute[] { parametersAttribute }; 
        } 
    }
}
