using System;
using System.Windows.Forms;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.ANSI.GUI
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

        public IParameters GetParameters(IRand rand, string keyOID, KeyUsage keyUsage)
        {
            if (keyOID == ASN1.ISO.PKCS.PKCS1.OID.rsa)
            {
                // проверить возможность диалога
                if (rand.Window == null) return new RSA.Parameters(1024, null);
                else { 
                    // создать диалог выбора параметров ключа
                    CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new RSAControl()); 

                    // отобразить диалог
                    DialogResult dialogResult = Aladdin.GUI.ModalView.Show(
                        (IWin32Window)rand.Window, dialog
                    ); 
                    // вернуть выбранные параметры
                    if (dialogResult == DialogResult.OK) return dialog.Parameters; 
            
                    // при отмене выбросить исключение
                    throw new OperationCanceledException(); 
                }
            }
            if (keyOID == ASN1.ANSI.OID.x942_dh_public_key)
            {
                // указать фабрику кодирования
                KeyFactory keyFactory = new X942.KeyFactory(keyOID); 

			    // раскодировать параметры ключа
			    return keyFactory.DecodeParameters(ASN1.ANSI.X942.DomainParameters.Ephemeral); 
            }
            if (keyOID == ASN1.ANSI.OID.x957_dsa)
            {
                // указать фабрику кодирования
                KeyFactory keyFactory = new X957.KeyFactory(keyOID); 

			    // раскодировать параметры ключа
			    return keyFactory.DecodeParameters(ASN1.ANSI.X957.DssParms.Ephemeral); 
            }
            if (keyOID == ASN1.ANSI.OID.x962_ec_public_key)
            {
                // проверить возможность диалгоа
                if (rand.Window == null) { KeyFactory keyFactory = new X962.KeyFactory(keyOID); 

                    // раскодировать параметры ключа
                    return keyFactory.DecodeParameters(new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_curves_prime256v1)); 
                }
                else { 
                    // создать диалог выбора параметров ключа
                    CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new ECControl()); 

                    // отобразить диалог
                    DialogResult dialogResult = Aladdin.GUI.ModalView.Show(
                        (IWin32Window)rand.Window, dialog
                    ); 
                    // вернуть выбранные параметры
                    if (dialogResult == DialogResult.OK) return dialog.Parameters; 
            
                    // при отмене выбросить исключение
                    throw new OperationCanceledException(); 
                }
            }
            throw new NotSupportedException(); 
        }
        public PBE.PBECulture GetPBECulture(object window, string keyOID)
        {
            // создать диалог выбора криптографической культуры
            CAPI.GUI.CultureDialog dialog = new CAPI.GUI.CultureDialog( 
                new PKCSControl(pbeParameters), 
                new NISTControl(pbeParameters)
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
