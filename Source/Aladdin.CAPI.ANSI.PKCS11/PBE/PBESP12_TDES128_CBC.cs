using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования по паролю PKCS12 TDES-128-CBC
    ///////////////////////////////////////////////////////////////////////////
    public class PBESP12_TDES128_CBC : CAPI.PKCS11.PBE.PBESP12
    {
	    // конструктор 
	    public PBESP12_TDES128_CBC(CAPI.PKCS11.Applet applet, ulong algID, byte[] salt, int iterations)
	    
            // сохранить переданные параметры
            : base(applet, algID, salt, iterations, Keys.TDES.Instance) {} 
	    
        // размер блока алгоритма
	    public override int BlockSize { get { return 8; }}
	    // размер ключа
	    protected override int KeyLength { get { return 16; }}  
    
	    // создать алгоритм шифрования
	    protected override CAPI.Cipher CreateCipher(byte[] iv)
        {
            // указать параметры алгоритма
            Mechanism parameters = new Mechanism(API.CKM_DES3_CBC_PAD, iv); 

            // создать алгоритм шифрования
            CAPI.Cipher cipher = Creator.CreateCipher(
                Applet.Provider, Applet, parameters, KeyLength
            ); 
            // проверить наличие алгоритма
            if (cipher == null) throw new NotSupportedException(); return cipher; 
        }
	    // атрибуты ключа
	    public override CAPI.PKCS11.Attribute[] GetKeyAttributes() 
        { 
            // дополнительные атрибуты ключа
            return new CAPI.PKCS11.Attribute[] {
                Applet.Provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_DES2)
            }; 
        } 
    }
}
