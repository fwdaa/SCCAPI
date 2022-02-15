package aladdin.capi.pkcs12;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.capi.Certificate; 
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import java.io.*; 
import java.security.*; 

///////////////////////////////////////////////////////////////////////////
// Подписанный контейнер PKCS12
///////////////////////////////////////////////////////////////////////////
public class PfxSignedContainer extends PfxContainer implements IPfxSignedContainer
{
    // личный ключ и сертификат
	private IPrivateKey privateKey; private Certificate certificate;
 
	// конструктор
	public PfxSignedContainer(PFX content, Factory factory, IRand rand) throws IOException
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
	@Override public final void setSignKeys(IPrivateKey privateKey, Certificate certificate)
        throws IOException, SignatureException
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
