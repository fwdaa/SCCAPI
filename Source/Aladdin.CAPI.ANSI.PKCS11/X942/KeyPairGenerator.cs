using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.X942
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм генерации ключей DH
    ///////////////////////////////////////////////////////////////////////////
    public class KeyPairGenerator : CAPI.PKCS11.KeyPairGenerator
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
	    // параметры генерации
	    private ANSI.X942.IParameters parameters; 

	    // конструктор
	    public KeyPairGenerator(CAPI.PKCS11.Applet applet, SecurityObject scope, 
            IRand rand, ANSI.X942.IParameters parameters)
	    
		    // сохранить переданные параметры
		    : base(applet, scope, rand) { this.parameters = parameters; }
	    
	    // сгенерировать пару ключей
	    public override KeyPair Generate(String keyOID, KeyUsage keyUsage) 
        {
            // указать программный алгоритм генерации
            using (CAPI.KeyPairGenerator generator = 
                new ANSI.X942.KeyPairGenerator(
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
		    return new Mechanism(API.CKM_X9_42_DH_KEY_PAIR_GEN); 
	    }
	    // атрибуты открытого ключа
        protected override CAPI.PKCS11.Attribute[] GetPublicAttributes(string keyOID) 
        { 
            // закодировать параметры генерации
            byte[] p = Math.Convert.FromBigInteger(parameters.P, Endian);
            byte[] q = Math.Convert.FromBigInteger(parameters.Q, Endian);
            byte[] g = Math.Convert.FromBigInteger(parameters.G, Endian);
        
            // создать список атрибутов
            return new CAPI.PKCS11.Attribute[] { 

                // указать параметры
                Applet.Provider.CreateAttribute(API.CKA_PRIME,    p), 
                Applet.Provider.CreateAttribute(API.CKA_SUBPRIME, q),  
                Applet.Provider.CreateAttribute(API.CKA_BASE,     g) 
            }; 
        } 
    }
}
