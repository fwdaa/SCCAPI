using System;
using System.Security; 
using System.Collections.Generic;
using System.Globalization;
using System.Windows.Forms;
using System.Security.Cryptography.X509Certificates;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Окно отображения сертификатов
	///////////////////////////////////////////////////////////////////////////
	public partial class CertificatesDialog : Form
	{
		// отобразить диалог
		public static Certificate[] Show(IWin32Window parent, Certificate[] certificates)
		{
			// создать диалог выбора контейнера
			CertificatesDialog dialog = new CertificatesDialog(certificates); 

            // отобразить диалог
            DialogResult result = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// проверить результат диалога
			if (result == DialogResult.OK) return dialog.Certificates;

			// вернуть пустой список сертификатов
            return new Certificate[0]; 
		}
		internal CertificatesDialog(Certificate[] certificates) 
		{ 
			// инициализировать дочерние элементы
			InitializeComponent(); buttonOK.Enabled = false; 

            // для всех сертификатов
            foreach (CAPI.Certificate certificate in certificates)
            { 
			    // определить имя субъекта
			    string   subject  = certificate.SubjectName; 
			    KeyUsage keyUsage = certificate.KeyUsage;  

			    // определить начало срока действия
			    string notBefore = certificate.NotBefore.ToString(
				    "d", CultureInfo.CurrentUICulture
			    ); 
			    // определить окончание срока действия
			    string notAfter = certificate.NotAfter.ToString(
				    "d", CultureInfo.CurrentUICulture
			    ); 
                // получить описание способа использования
                string description = Utils.GetDescription(keyUsage); 

			    // указать информацию о новом элементе в список
			    ListViewItem item = new ListViewItem(new string[] { 
				    subject, notBefore, notAfter, description
			    });
			    // указать строку подсказки
			    item.ToolTipText = String.Format("{0} {1} {2} {3}", 
				    subject, notBefore, notAfter, description
			    ); 
                // добавить созданную информацию
			    item.Tag = certificate; listView.Items.Add(item); 
            }
		}
		public CertificatesDialog() { InitializeComponent(); }

        private void OnSelectedIndexChanged(object sender, EventArgs e)
        {
            // указать доступность кнопки
            buttonOK.Enabled = listView.SelectedItems.Count > 0; 
        }
		private void OnDoubleClick(object sender, MouseEventArgs e)
		{
            // получить источник события
            ListViewHitTestInfo info = listView.HitTest(e.X, e.Y);

            // проверить наличие элемента
            if (info.Item == null) return; ListViewItem item = info.Item as ListViewItem;

    	    // получить выделенный элемент
		    Certificate certificate = (Certificate)item.Tag; 

		    // отобразить сертификат
		    CertificateDialog.Show(Handle, new Certificate[] { certificate }); 
		}
        public Certificate[] Certificates { get
        { 
            // создать список сертификатов
            List<Certificate> certificates = new List<Certificate>(); 

            // для всех выбранных элементов
            foreach (ListViewItem item in listView.SelectedItems)
            {
                // добавить сертификат в список
                certificates.Add((Certificate)item.Tag); 
            }
            return certificates.ToArray(); 
        }}
	}
}
