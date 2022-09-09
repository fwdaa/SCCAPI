using System;
using System.IO;
using System.Windows.Forms;
using System.Collections.Generic;
using System.ComponentModel;
using Aladdin.GUI; 

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог генерации ключевой пары
	///////////////////////////////////////////////////////////////////////////
	public partial class CertRequestDialog : Form
	{
        // имя субъекта и допустимые способы использования ключа
		private ASN1.IEncodable subject; private KeyUsage keyUsage; 

		// конструктор
		public CertRequestDialog(KeyUsage keyUsage) { this.keyUsage = keyUsage; 
		
			// сохранить переданные параметры
			InitializeComponent(); dateTimeFrom.Value = DateTime.Now;

			// установить срок действия по умолчанию
			dateTimeBefore.Value = dateTimeFrom.Value.AddYears(1); 
            
            // указать допустимый выбор
            checkBoxCertificateSignature.Enabled = checkBoxCrlSignature.Enabled = false; 
                
            // указать допустимый выбор
            checkBoxCA.Enabled = checkBoxPathLen.Enabled = false; 

			// указать допустимый выбор
			checkBoxDigitalSignature.Enabled = ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None); 
			checkBoxNonRepudiation  .Enabled = ((keyUsage & KeyUsage.NonRepudiation  ) != KeyUsage.None); 
			checkBoxKeyEncipherment .Enabled = ((keyUsage & KeyUsage.KeyEncipherment ) != KeyUsage.None); 
			checkBoxKeyAgreement    .Enabled = ((keyUsage & KeyUsage.KeyAgreement    ) != KeyUsage.None); 
			checkBoxDataEncipherment.Enabled = ((keyUsage & KeyUsage.DataEncipherment) != KeyUsage.None); 

            // указать допустимый выбор
            checkBoxEncipherOnly.Enabled = checkBoxDecipherOnly.Enabled = false;

            // указать доступность элемента
            textBoxPathLen.Enabled = false; textBoxPathLen.Text = "N/A"; 

            // указать допустимый выбор
            checkBoxServerAuth     .Enabled = checkBoxClientAuth     .Enabled = false; 
            checkBoxCodeSigning    .Enabled = checkBoxOCSPSigning    .Enabled = false; 
            checkBoxTimeStamping   .Enabled = checkBoxEmailProtection.Enabled = false; 
        }
        // выбранное имя субъекта
        public ASN1.IEncodable Subject { get { return subject; }}

        // срок действия ключа
        public DateTime NotBefore { get { return dateTimeFrom.Value;   }}
        public DateTime NotAfter  { get { return dateTimeBefore.Value; }}

        // способ использования ключа
        public KeyUsage KeyUsage { get { CAPI.KeyUsage keyUsage = CAPI.KeyUsage.None; 
            
			// получить способ использования ключа
		    if (checkBoxDigitalSignature    .Checked) keyUsage |= KeyUsage.DigitalSignature; 
            if (checkBoxCertificateSignature.Checked) keyUsage |= KeyUsage.CertificateSignature; 
		    if (checkBoxCrlSignature        .Checked) keyUsage |= KeyUsage.CrlSignature; 
            if (checkBoxNonRepudiation      .Checked) keyUsage |= KeyUsage.NonRepudiation; 
    	    if (checkBoxKeyEncipherment     .Checked) keyUsage |= KeyUsage.KeyEncipherment; 
            if (checkBoxKeyAgreement        .Checked) keyUsage |= KeyUsage.KeyAgreement; 
		    if (checkBoxDataEncipherment    .Checked) keyUsage |= KeyUsage.DataEncipherment; 
            if (checkBoxEncipherOnly        .Checked) keyUsage |= KeyUsage.EncipherOnly; 
            if (checkBoxDecipherOnly        .Checked) keyUsage |= KeyUsage.DecipherOnly; 

            return keyUsage; 
        }}
        // расширенные способы использования ключа
        public string[] ExtendedKeyUsage { get { 

            // создать список расширенных способов использования
            List<String> extKeyUsages = new List<String>(); 

            // заполнить список расширенных способов использования
            if (checkBoxServerAuth     .Checked) extKeyUsages.Add(ASN1.ISO.PKIX.OID.kp_serverAuth     ); 
            if (checkBoxClientAuth     .Checked) extKeyUsages.Add(ASN1.ISO.PKIX.OID.kp_clientAuth     ); 
            if (checkBoxCodeSigning    .Checked) extKeyUsages.Add(ASN1.ISO.PKIX.OID.kp_codeSigning    ); 
            if (checkBoxEmailProtection.Checked) extKeyUsages.Add(ASN1.ISO.PKIX.OID.kp_emailProtection); 
            if (checkBoxTimeStamping   .Checked) extKeyUsages.Add(ASN1.ISO.PKIX.OID.kp_timeStamping   ); 
            if (checkBoxOCSPSigning    .Checked) extKeyUsages.Add(ASN1.ISO.PKIX.OID.kp_ocspSigning    ); 
            if (checkBoxAnyExtKeyUsage .Checked) extKeyUsages.Add(ASN1.ISO.PKIX.OID.ce_extKeyUsage_any); 
            
            // вернуть список расширенных способов использования
            return (extKeyUsages.Count > 0) ? extKeyUsages.ToArray() : null; 
        }}
        // основные ограничения сертификата
        public ASN1.ISO.PKIX.CE.BasicConstraints BasicConstraints { get
        {
            // проверить наличие ограничений
            if (!checkBoxCA.Checked) return null; ASN1.Integer pathLen = null; 

            // при указании максимальной глубины
            if (checkBoxPathLen.Checked) pathLen = new ASN1.Integer(Int32.Parse(textBoxPathLen.Text)); 

            // вернуть основные ограничения
            return new ASN1.ISO.PKIX.CE.BasicConstraints(ASN1.Boolean.True, pathLen); 
        }}

		private void OnSubjectValidating(object sender, CancelEventArgs e)
		{
			// проверить наличие имени субъекта
			if (textBoxSubject.Text.Length == 0) 
			{ 
				// получить сообщение об ошибке 
				string message = Resource.ErrorSubjectName; e.Cancel = true; 

				// вывести описание ошибки
				MessageBox.Show(this, message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); return;   
			}
			// закодировать имя субъекта
			try { subject = new ASN1.ISO.PKIX.RelativeDistinguishedNames(textBoxSubject.Text); buttonOK.Enabled = true; }
			
			// при возникновении ошибки
			catch (Exception ex) { e.Cancel = true; buttonOK.Enabled = false;

				// выделить имя субъекта
				textBoxSubject.Select(0, textBoxSubject.Text.Length);

				// вывести описание ошибки
				MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);  
			}
		}
        private void OnDigitalSignatureCheckChanged(object sender, EventArgs e)
        {
            // указать доступность элемента
            checkBoxCA         .Enabled = checkBoxDigitalSignature.Checked; 
            checkBoxCodeSigning.Enabled = checkBoxDigitalSignature.Checked; 
            checkBoxOCSPSigning.Enabled = checkBoxDigitalSignature.Checked; 

            // в зависимости от значений элементов
            if (checkBoxDigitalSignature.Checked)
            {
                // указать доступность элемента
                checkBoxServerAuth     .Enabled = checkBoxClientAuth  .Enabled = true; 
                checkBoxEmailProtection.Enabled = checkBoxTimeStamping.Enabled = true; 
            }
            // установить значение элемента
            else { checkBoxCA.Checked = false; 

                // установить значение элемента
                checkBoxCodeSigning.Checked = checkBoxOCSPSigning.Checked = false; 

                // указать доступность элемента
                if (!checkBoxNonRepudiation.Checked) checkBoxTimeStamping.Enabled = false;

                // в зависимости от значений элементов
                if (!checkBoxKeyEncipherment.Checked && !checkBoxKeyAgreement.Checked)
                {
                    // указать доступность элемента
                    checkBoxServerAuth.Enabled = checkBoxClientAuth.Enabled = false; 

                    // указать доступность элемента
                    if (!checkBoxNonRepudiation.Checked) checkBoxEmailProtection.Enabled = false;
                }
            }
        }
        private void OnNonRepudiationCheckChanged(object sender, EventArgs e)
        {
            // в зависимости от значений элементов
            if (checkBoxNonRepudiation.Checked)
            {
                // указать доступность элемента
                checkBoxEmailProtection.Enabled = checkBoxTimeStamping.Enabled = true; 
            }
            else { 
                // указать доступность элемента
                if (!checkBoxDigitalSignature.Checked) checkBoxTimeStamping.Enabled = false;

                // в зависимости от значений элементов
                if (!checkBoxKeyEncipherment.Checked && !checkBoxKeyAgreement.Checked)
                {
                    // указать доступность элемента
                    if (!checkBoxDigitalSignature.Checked) checkBoxEmailProtection.Enabled = false;
                }
            }
        }
        private void OnKeyEnciphermentCheckedChanged(object sender, EventArgs e)
        {
             // в зависимости от значений элементов
             if (checkBoxKeyEncipherment.Checked) { checkBoxEmailProtection.Enabled = true; 

                // указать доступность элемента
                checkBoxServerAuth.Enabled = checkBoxClientAuth.Enabled = true; 
             }
             else {
                // в зависимости от значений элементов
                if (!checkBoxDigitalSignature.Checked && !checkBoxKeyAgreement.Checked)
                {
                    // указать доступность элемента
                    checkBoxServerAuth.Enabled = checkBoxClientAuth.Enabled = false; 

                    // указать доступность элемента
                    if (!checkBoxNonRepudiation.Checked) checkBoxEmailProtection.Enabled = false;
                }
             }
        }
        private void OnKeyAgreementCheckChanged(object sender, EventArgs e)
        {
            // изменить состояние выбора
            checkBoxEncipherOnly.Checked = checkBoxDecipherOnly.Checked = false;

            // указать доступность выбора
            checkBoxEncipherOnly.Enabled = checkBoxKeyAgreement.Checked; 
            checkBoxDecipherOnly.Enabled = checkBoxKeyAgreement.Checked; 

             // в зависимости от значений элементов
             if (checkBoxKeyAgreement.Checked) { checkBoxEmailProtection.Enabled = true; 

                // указать доступность элемента
                checkBoxServerAuth.Enabled = checkBoxClientAuth.Enabled = true; 
             }
             else {
                // в зависимости от значений элементов
                if (!checkBoxDigitalSignature.Checked && !checkBoxKeyEncipherment.Checked)
                {
                    // указать доступность элемента
                    checkBoxServerAuth.Enabled = checkBoxClientAuth.Enabled = false; 

                    // указать доступность элемента
                    if (!checkBoxNonRepudiation.Checked) checkBoxEmailProtection.Enabled = false;
                }
             }
        }
        private void OnEncipherOnlyCheckChanged(object sender, EventArgs e)
        {
            // изменить состояние выбора
            checkBoxDecipherOnly.Checked = !checkBoxEncipherOnly.Checked; 
        }
        private void OnDecipherOnlyCheckChanged(object sender, EventArgs e)
        {
            // изменить состояние выбора
            checkBoxEncipherOnly.Checked = !checkBoxDecipherOnly.Checked; 
        }
        private void OnCACheckedChanged(object sender, EventArgs e)
        {
            // указать значение элемента
            checkBoxCertificateSignature.Checked = checkBoxCA.Checked; 

            // указать доступность элемента
            if (!checkBoxCA.Checked) 
            {
                // указать доступность элемента
                checkBoxCrlSignature.Enabled = false; 

                // указать значение элемента
                checkBoxCrlSignature.Checked = false; 
            }
            else { 
                // при допустимости использования ключа
                if ((keyUsage & KeyUsage.CrlSignature) != KeyUsage.None) 
                {
                    // указать доступность элемента
                    checkBoxCrlSignature.Enabled = true; 
                }
            }
            // указать доступность элемента
            checkBoxPathLen.Enabled = checkBoxCA.Checked; 

            // указать значение элемента
            if (!checkBoxPathLen.Enabled) checkBoxPathLen.Checked = false; 
        }
        private void OnPathLenCheckedChanged(object sender, EventArgs e)
        {
            // указать доступность элемента
            textBoxPathLen.Enabled = checkBoxPathLen.Checked; 

            // указать значение элемента
            textBoxPathLen.Text = (textBoxPathLen.Enabled) ? "0" : "N/A"; 
        }
        private void OnPathLenValidating(object sender, CancelEventArgs e)
        {
            // проверить необходимость проверки
            buttonOK.Enabled = true; if (!checkBoxPathLen.Checked) return; 

			// проверить корректностиь размера
			uint value; if (!UInt32.TryParse(textBoxPathLen.Text, out value))
            {
			    // указать недоступность кнопки
			    e.Cancel = true; buttonOK.Enabled = false;

				// выделить элемент управления
				textBoxPathLen.Select(0, textBoxPathLen.Text.Length);

				// вывести описание ошибки
				MessageBox.Show(this, Resource.ErrorPathLength, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);  
			}
        }
	}
}
