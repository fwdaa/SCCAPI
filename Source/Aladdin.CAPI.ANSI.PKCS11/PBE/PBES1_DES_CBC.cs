using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования по паролю PBES1 DES-CBC
    ///////////////////////////////////////////////////////////////////////////
    public class PBES1_DES_CBC : CAPI.PKCS11.PBE.PBES1
    {
	    // конструктор 
	    public PBES1_DES_CBC(CAPI.PKCS11.Applet applet, ulong algID, byte[] salt, int iterations)
	    
            // сохранить переданные параметры
            : base(applet, algID, salt, iterations, Keys.DES.Instance) {}
	    
        // размер блока алгоритма
	    public override int BlockSize { get { return 8; }} 
	    // размер ключа
	    protected override int KeyLength { get { return 8; }}  
    
	    // создать алгоритм шифрования
	    protected override CAPI.Cipher CreateCipher(byte[] iv)
        {
            // указать параметры алгоритма
            Mechanism parameters = 
                new Mechanism(API.CKM_DES_CBC_PAD, iv); 
        
            // создать алгоритм шифрования
            CAPI.Cipher cipher = Creator.CreateCipher(
                Applet.Provider, Applet, parameters, 0
            ); 
            // проверить наличие алгоритма
            if (cipher == null) throw new NotSupportedException(); return cipher; 
        }
	    // атрибуты ключа
	    public override CAPI.PKCS11.Attribute[] GetKeyAttributes() 
        { 
            // дополнительные атрибуты ключа
            return new CAPI.PKCS11.Attribute[] {
                Applet.Provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_DES)
            }; 
        } 
    }
}
