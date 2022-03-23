using System;
using System.Windows.Forms;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.STB.GUI
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
            if (keyOID == ASN1.STB.OID.stb34101_bign_pubKey)
            {
                if (rand.Window == null)
                {
                    // указать фабрику кодирования
                    KeyFactory keyFactory = new STB34101.KeyFactory(keyOID); 

	                // закодировать параметры ключа
                    ASN1.IEncodable encoded = new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_curve256_v1); 

                    // раскодировать параметры ключа
                    return keyFactory.DecodeParameters(encoded);
                }
                else { 
                    // создать диалог выбора параметров ключа
                    CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl34101()); 

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
            if (keyOID == ASN1.STB.OID.stb11762_bds_pubKey || 
                keyOID == ASN1.STB.OID.stb11762_pre_bds_pubKey)
            {
                if (rand.Window == null)
                {
                    // указать фабрику кодирования
                    KeyFactory keyFactory = new STB11762.BDSBDHKeyFactory(keyOID); 

		            // закодировать параметры ключа
                    ASN1.IEncodable encoded = ASN1.Explicit.Encode(ASN1.Tag.Context(2), 
                        new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_params6)
                    ); 
                    // раскодировать параметры ключа
                    return keyFactory.DecodeParameters(encoded);
                }
                else { 
                    // создать диалог выбора параметров ключа
                    CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl11762SX()); 

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
            if (keyOID == ASN1.STB.OID.stb11762_bdsbdh_pubKey || 
                keyOID == ASN1.STB.OID.stb11762_pre_bdsbdh_pubKey)
            {
                if (rand.Window == null)
                {
                    // указать фабрику кодирования
                    KeyFactory keyFactory = new STB11762.BDSKeyFactory(keyOID);

		            // закодировать параметры ключа
                    ASN1.IEncodable encoded = ASN1.Explicit.Encode(ASN1.Tag.Context(0), 
                        new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_params6_bds)
                    ); 
                    // раскодировать параметры ключа
                    return keyFactory.DecodeParameters(encoded);
                }
                else { 
                    // создать диалог выбора параметров ключа
                    CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl11762S()); 

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
        public PBE.PBECulture GetCulture(object window, string keyOID)
        { 
            // создать диалог выбора криптографической культуры
            CAPI.GUI.CultureDialog dialog = new CAPI.GUI.CultureDialog(
                new CAPI.ANSI.GUI.PKCSControl    (pbeParameters), 
                new CAPI.ANSI.GUI.NISTControl    (pbeParameters), 
                new CAPI.STB .GUI.STB34101Control(pbeParameters), 
                new CAPI.STB .GUI.STB1176Control (pbeParameters)
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
