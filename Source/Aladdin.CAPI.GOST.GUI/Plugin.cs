using System;
using System.Windows.Forms;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.GOST.GUI
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
            if (keyOID == ASN1.GOST.OID.gostR3410_1994)
            {
                if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                { 
                    if (rand.Window == null)
                    { 
                        // указать фабрику кодирования ключей
                        KeyFactory keyFactory = new GOSTR3410.DHKeyFactory(keyOID); 

                        // закодировать все параметры
                        ASN1.IEncodable encoded = new ASN1.GOST.GOSTR3410PublicKeyParameters2001(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.exchanges_A), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A)
                        ); 
                        // раскодировать параметры
                        return keyFactory.DecodeParameters(encoded); 
                    }
                    else { 
                        // создать диалог выбора параметров ключа
                        CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl1994X()); 

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
                else { 
                    if (rand.Window == null)
                    { 
                        // указать фабрику кодирования ключей
                        KeyFactory keyFactory = new GOSTR3410.DHKeyFactory(keyOID); 

                        // закодировать все параметры
                        ASN1.IEncodable encoded = new ASN1.GOST.GOSTR3410PublicKeyParameters2001(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.signs_A), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A)
                        ); 
                        // раскодировать параметры
                        return keyFactory.DecodeParameters(encoded); 
                    }
                    else { 
                        // создать диалог выбора параметров ключа
                        CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl1994S()); 

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
            }
            if (keyOID == ASN1.GOST.OID.gostR3410_2001)
            {
                if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                { 
                    if (rand.Window == null)
                    { 
                        // указать фабрику кодирования ключей
                        KeyFactory keyFactory = new GOSTR3410.ECKeyFactory(keyOID); 

                        // закодировать все параметры
                        ASN1.IEncodable encoded = new ASN1.GOST.GOSTR3410PublicKeyParameters2001(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.ecc_exchanges_A), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A)
                        ); 
                        // раскодировать параметры
                        return keyFactory.DecodeParameters(encoded); 
                    }
                    else { 
                        // создать диалог выбора параметров ключа
                        CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl2001X()); 

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
                else { 
                    if (rand.Window == null)
                    {
                        // указать фабрику кодирования ключей
                        KeyFactory keyFactory = new GOSTR3410.ECKeyFactory(keyOID); 

                        // закодировать все параметры
                        ASN1.IEncodable encoded = new ASN1.GOST.GOSTR3410PublicKeyParameters2001(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.ecc_signs_A), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A)
                        ); 
                        // раскодировать параметры
                        return keyFactory.DecodeParameters(encoded); 
                    }
                    else { 
                        // создать диалог выбора параметров ключа
                        CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl2001S()); 

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
            }
            if (keyOID == ASN1.GOST.OID.gostR3410_2012_256)
            {
                if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                { 
                    if (rand.Window == null)
                    { 
                        // указать фабрику кодирования ключей
                        KeyFactory keyFactory = new GOSTR3410.ECKeyFactory(keyOID); 

                        // закодировать все параметры
                        ASN1.IEncodable encoded = new ASN1.GOST.GOSTR3410PublicKeyParameters2012(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.ecc_exchanges_A), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256) 
                        ); 
                        // раскодировать параметры
                        return keyFactory.DecodeParameters(encoded); 
                    }
                    else { 
                        // создать диалог выбора параметров ключа
                        CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl2012_256X());
 
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
                else { 
                    if (rand.Window == null)
                    { 
                        // указать фабрику кодирования ключей
                        KeyFactory keyFactory = new GOSTR3410.ECKeyFactory(keyOID); 

                        // закодировать все параметры
                        ASN1.IEncodable encoded = new ASN1.GOST.GOSTR3410PublicKeyParameters2012(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.ecc_signs_A), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256) 
                        ); 
                        // раскодировать параметры
                        return keyFactory.DecodeParameters(encoded); 
                    }
                    else { 
                        // создать диалог выбора параметров ключа
                        CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl2012_256S()); 

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
            }
            if (keyOID == ASN1.GOST.OID.gostR3410_2012_512)
            {
                if (rand.Window == null)
                { 
                        // указать фабрику кодирования ключей
                        KeyFactory keyFactory = new GOSTR3410.ECKeyFactory(keyOID); 

                        // закодировать все параметры
                        ASN1.IEncodable encoded = new ASN1.GOST.GOSTR3410PublicKeyParameters2012(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.ecc_tc26_2012_512A), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_512) 
                        ); 
                        // раскодировать параметры
                        return keyFactory.DecodeParameters(encoded); 
                }
                else { 
                    // создать диалог выбора параметров ключа
                    CAPI.GUI.ParametersDialog dialog = new CAPI.GUI.ParametersDialog(new KeyControl2012_512()); 

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
                new CAPI.ANSI.GUI.PKCSControl   (pbeParameters), 
                new CAPI.ANSI.GUI.NISTControl   (pbeParameters), 
                new CAPI.GOST.GUI.CultureControl(pbeParameters)
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
