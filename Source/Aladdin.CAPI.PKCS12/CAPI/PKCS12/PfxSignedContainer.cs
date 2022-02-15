using System;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Подписанный контейнер PKCS12
	///////////////////////////////////////////////////////////////////////////
	public class PfxSignedContainer : PfxContainer, IPfxSignedContainer
	{
        //  открытый ключ и сертификат
		private IPrivateKey privateKey; private Certificate certificate;
 
		// конструктор
		public PfxSignedContainer(ASN1.ISO.PKCS.PKCS12.PFX content, IRand rand) 
			
            // инициализировать переменные
			: base(content, rand) { this.privateKey = null; this.certificate = null; }

        // освободить выделенные ресурсы
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
		    RefObject.Release(privateKey); base.OnDispose();
        }
        // личный ключ и сертификат
        public IPrivateKey SignPrivateKey  { get { return privateKey;  }} 
        public Certificate SignCertificate { get { return certificate; }}

		// установить ключи
		public void SetSignKeys(IPrivateKey privateKey, Certificate certificate)
		{
            // освободить выделенные ресурсы
            RefObject.Release(this.privateKey); this.privateKey = null; 

			// сохранить переданные параметры
			this.privateKey = RefObject.AddRef(privateKey); this.certificate = certificate; 

			// преобразовать тип данных
			ASN1.ISO.PKCS.PKCS7.SignedData signedData = 
				new ASN1.ISO.PKCS.PKCS7.SignedData(content.AuthSafe.Inner); 

			// проверить подпись данных
            CMS.VerifySign(privateKey.Factory, null, certificate, signedData); 
		}
		// переустановить ключи
		public void ChangeSignKeys(IPrivateKey privateKey, Certificate certificate)
		{
			// проверить наличие сертификата
			if (this.certificate == null || this.privateKey == null) throw new UnauthorizedAccessException();

			// сохранить старые ключи
			IPrivateKey oldPrivateKey = this.privateKey; Certificate oldCertificate = this.certificate; 

            // указать новые ключи
            this.privateKey = RefObject.AddRef(privateKey); this.certificate = certificate; 

            // обработать изменение данных
            try { Change(); RefObject.Release(oldPrivateKey); } catch { RefObject.Release(privateKey); 

                // восстановить ключи
                this.privateKey = oldPrivateKey; this.certificate = oldCertificate; throw; 
            }
        }
		protected override void OnChange(ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe authenticatedSafe)
		{
			// проверить наличие ключей
			if (privateKey == null || certificate == null) throw new UnauthorizedAccessException(); 

			// преобразовать тип данных
			ASN1.ISO.PKCS.PKCS7.SignedData signedData = 
				new ASN1.ISO.PKCS.PKCS7.SignedData(content.AuthSafe.Inner); 

			// извлечь информацию подписи
			ASN1.ISO.PKCS.PKCS7.SignerInfo signerInfo = signedData.SignerInfos[0]; 

			// сохранить новое содержимое
			content = Pfx.CreateSignedContainer(privateKey.Factory, Rand, 
                signedData.Version, authenticatedSafe, privateKey, certificate, 
				signerInfo.DigestAlgorithm, signerInfo.SignatureAlgorithm, 
				signerInfo.SignedAttrs, signerInfo.UnsignedAttrs, 
				signedData.Certificates, signedData.Crls
			); 
		}
	}
}
