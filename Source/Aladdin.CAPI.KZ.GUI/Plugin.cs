using System;
using System.Windows.Forms;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.KZ.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Расширение криптографических культур
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class Plugin : RefObject, ICulturePlugin 
    { 
        // параметры шифрования по паролю
        private PBE.PBEParameters pbeParameters; 

        // конструктор
        public Plugin(PBE.PBEParameters pbeParameters) 
            
            // сохранить переданные параметры 
            { this.pbeParameters = pbeParameters; } 

        public IParameters GetKeyParameters(IRand rand, string keyOID, KeyUsage keyUsage)
        {
            if (keyOID == ASN1.KZ.OID.gamma_key_rsa_1024     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1536     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_2048     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_3072     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_4096     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1024_xch ||
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1536_xch ||
                keyOID == ASN1.KZ.OID.gamma_key_rsa_2048_xch ||
                keyOID == ASN1.KZ.OID.gamma_key_rsa_3072_xch ||
                keyOID == ASN1.KZ.OID.gamma_key_rsa_4096_xch)
            {
                // указать фабрику кодирования ключей
                RSA.KeyFactory keyFactory = new RSA.KeyFactory(keyOID); 

                // указать параметры
                return keyFactory.DecodeParameters(ASN1.Null.Instance); 
            }
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a     || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b     ||
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_c     || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b_xch)
            {
                // указать фабрику кодирования ключей
                GOST34310.ECKeyFactory keyFactory = new GOST34310.ECKeyFactory(keyOID); 

                // указать параметры
                return keyFactory.DecodeParameters(ASN1.Null.Instance);
            }
            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
        public PBE.PBECulture GetPBECulture(object window, string keyOID)
        {
            // создать диалог выбора криптографической культуры
            CAPI.GUI.CultureDialog dialog = new CAPI.GUI.CultureDialog(
                new CAPI.ANSI.GUI.PKCSControl   (pbeParameters), 
                new CAPI.ANSI.GUI.NISTControl   (pbeParameters), 
                new CAPI.KZ  .GUI.CultureControl(pbeParameters)
            ); 
            // отобразить диалог
            DialogResult dialogResult = Aladdin.GUI.ModalView.Show(
                (IWin32Window)window, dialog
            ); 
            // вернуть выбранную культуру
            if (dialogResult == DialogResult.OK) return dialog.Culture; 
           
            // при отмене выбросить исключение
            throw new OperationCanceledException(); 
        }
    }
}
