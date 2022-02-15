package aladdin.capi.pkcs12;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.capi.Certificate; 
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import java.io.*; 
import java.security.*; 

///////////////////////////////////////////////////////////////////////////
// Подписанный зашифрованный на открытом ключ контейнер PKCS12 
///////////////////////////////////////////////////////////////////////////
public class PfxSignedEnvelopedContainer 
    extends PfxEnvelopedContainer implements IPfxSignedContainer
{
    // личный ключ и сертификат
	private IPrivateKey privateKey;	private Certificate certificate;
 
	// конструктор
	public PfxSignedEnvelopedContainer(PFX content, IRand rand) throws IOException
    {
		// сохранить переданные параметры
		super(content, rand); privateKey = null; certificate = null; 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
		RefObject.release(privateKey); super.onClose();
    }
    // личный ключ и сертификат
    @Override public final IPrivateKey signPrivateKey () { return privateKey;  } 
    @Override public final Certificate signCertificate() { return certificate; }
    
    // установить ключи
	@Override public final void setSignKeys(IPrivateKey privateKey, 
        Certificate certificate) throws IOException, SignatureException
	{
        // освободить выделенные ресурсы
        RefObject.release(this.privateKey); this.privateKey = null;
        
		// сохранить переданные параметры
		this.privateKey = RefObject.addRef(privateKey); this.certificate = certificate; 
        
		// преобразовать тип данных
		SignedData signedData = new SignedData(content.authSafe().inner()); 

		// проверить подпись данных
		CMS.verifySign(privateKey.factory(), null, certificate, signedData); 
	}
	// переустановить ключи
	@Override public void changeSignKeys(IPrivateKey privateKey, Certificate certificate)
        throws IOException 
	{
		// проверить наличие сертификата
		if (this.certificate == null || this.privateKey == null) throw new AuthenticationException();

		// сохранить старые ключи
		IPrivateKey oldPrivateKey = this.privateKey; Certificate oldCertificate = this.certificate; 

        // указать новые ключи
        this.privateKey = RefObject.addRef(privateKey); this.certificate = certificate; 

        // обработать изменение данных
        try { change(); RefObject.release(oldPrivateKey); } 
        
        // при возникновении ошибки
        catch (IOException e) { RefObject.release(privateKey); 

            // восстановить ключи
            this.privateKey = oldPrivateKey; this.certificate = oldCertificate; throw e; 
        }
    }
    // установить ключи
	public final void setKeys(IPrivateKey privateKey, 
        Certificate certificate, aladdin.capi.Culture culture)
        throws IOException, SignatureException
	{
		// проверить целостность 
        setSignKeys(privateKey, certificate); 
        
        // расшифровать контейнер
        setEnvelopeKeys(privateKey, certificate, culture);
	}
	// переустановить ключи
	public void changeKeys(IPrivateKey privateKey, Certificate certificate) throws IOException 
	{
		// проверить наличие сертификата
		if (this.certificate == null || this.privateKey == null) throw new AuthenticationException();

        // сохранить старый личный ключ
        try (IPrivateKey oldPrivateKey = RefObject.addRef(envelopePrivateKey())) 
        { 
            // сохранить старый сертификат
            Certificate oldCertificate = envelopeCertificate(); 
            
            // изменить ключи шифрования
            changeEnvelopeKeys(privateKey, certificate); 
            
            // изменить ключи проверки целостности
            try { changeSignKeys(privateKey, certificate); }

            // при ошибке восстановить старый ключ шифрования
            catch (IOException e) { changeEnvelopeKeys(oldPrivateKey, oldCertificate); throw e; }
        }
    }
	@Override protected void onChange(AuthenticatedSafe authenticatedSafe) throws IOException
	{
		// проверить наличие ключей
		if (privateKey == null || certificate == null) throw new AuthenticationException(); 

		// преобразовать тип данных
		SignedData signedData = new SignedData(content.authSafe().inner()); 

		// извлечь информацию подписи
		SignerInfo signerInfo = signedData.signerInfos().get(0); 

        // создать новое содержимое
        content = Pfx.createSignedContainer(privateKey.factory(), rand(), 
            signedData.version(), authenticatedSafe, privateKey, certificate,  
			signerInfo.digestAlgorithm(), signerInfo.signatureAlgorithm(), 
			signerInfo.signedAttrs(), signerInfo.unsignedAttrs(), 
			signedData.certificates(), signedData.crls()
        ); 
	}
}
