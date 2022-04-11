using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования по паролю PKCS12 RC2-CBC
    ///////////////////////////////////////////////////////////////////////////
    public class PBESP12_RC2_CBC : CAPI.PKCS11.PBE.PBESP12
    {
        // эффективное число битов ключа и размер ключа
        private int effectiveKeyBits; private int keyLength; 
    
	    // конструктор 
	    public PBESP12_RC2_CBC(CAPI.PKCS11.Applet applet, ulong algID, byte[] salt, int iterations)

            // сохранить переданные параметры
            : base(applet, algID, salt, iterations) 
        {
            // определить эффективное число битов ключа
            if (algID == API.CKM_PBE_SHA1_RC2_40_CBC ) effectiveKeyBits =  40; else 
            if (algID == API.CKM_PBE_SHA1_RC2_128_CBC) effectiveKeyBits = 128;  
            
            // при ошибке выбросить исключение
            else throw new NotSupportedException(); 

            // вычислить размер ключа
            keyLength = (effectiveKeyBits + 7) / 8; 
	    }
        // размер блока алгоритма
	    public override int BlockSize { get { return 8; }}
	    // фабрика ключа
	    protected override SecretKeyFactory DeriveKeyFactory
        {
            // фабрика ключа
            get { return new Keys.RC2(new int[] {keyLength}); }
        }
	    // создать алгоритм шифрования
	    protected override CAPI.Cipher CreateCipher(byte[] iv)
        {
            // указать параметры алгоритма
            Mechanism parameters = new Mechanism(
                API.CKM_RC2_CBC_PAD, 
                new Parameters.CK_RC2_CBC_PARAMS(effectiveKeyBits, iv)
            ); 
            // создать алгоритм шифрования
            CAPI.Cipher cipher = Creator.CreateCipher(
                Applet.Provider, Applet, parameters, keyLength
            ); 
            // проверить наличие алгоритма
            if (cipher == null) throw new NotSupportedException(); return cipher; 
        }
	    // атрибуты ключа
	    public override CAPI.PKCS11.Attribute[] GetKeyAttributes() 
        { 
            // дополнительные атрибуты ключа
            return new CAPI.PKCS11.Attribute[] {
                Applet.Provider.CreateAttribute(API.CKA_KEY_TYPE , API.CKK_RC2    ), 
                Applet.Provider.CreateAttribute(API.CKA_VALUE_LEN, (uint)keyLength) 
            }; 
        } 
    }
}
