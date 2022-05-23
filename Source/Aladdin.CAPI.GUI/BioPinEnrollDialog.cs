using System;
using System.Globalization;
using System.Collections.Generic;
using System.Windows.Forms;
using System.ComponentModel;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог регистрации отпечатков с указанием пин-кода
	///////////////////////////////////////////////////////////////////////////
    public partial class BioPinEnrollDialog : Form
    {
        // используемый таймер
        private System.Windows.Forms.Timer timer; 

		// биометрический провайдер и маскимальное число отпечатков
		private Bio.Provider provider; private int maxFingers; 

        // объект контейнера и элемент управления захватом отпечатка
        private SecurityObject obj; private Remoting.RemoteClientControl captureControl;
        
		// список созданных шаблонов
        private Dictionary<Bio.Finger, Bio.EnrollTemplate> enrollTemplates;

        // отобразить диалог для изменения
		public static void ShowChange(IWin32Window parent, SecurityObject obj, string user)
		{
			// создать диалог ввода пароля
			BioPinEnrollDialog dialog = new BioPinEnrollDialog(obj, user); 

            // отобразить диалог аутентификации
            DialogResult result = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// проверить результат диалога
			if (result == DialogResult.OK) return;

			// при ошибке выбросить исключение
			throw new OperationCanceledException();
        }
        // конструктор
        private BioPinEnrollDialog() { InitializeComponent(); }

		// конструктор
        public BioPinEnrollDialog(SecurityObject obj, string user)
        {
			// сохранить переданные параметры
            InitializeComponent(); this.obj = obj; timer = new Timer();
            
            // инициализировать переменные
            Auth.BiometricService service = null;

            // установить имя пользователя
            if (user != null) { comboBoxUser.Text = user; comboBoxUser.Enabled = false;

                // получить биометрический сервис
                service = (Auth.BiometricService)obj.GetAuthenticationService(
                    user, typeof(Auth.BiometricCredentials)
                );
            }
            // указать выбранный элемент
            else { comboBoxUser.SelectedIndex = 0; comboBoxUser.Enabled = true;

                // получить биометрический сервис
                service = (Auth.BiometricService)obj.GetAuthenticationService(
                    comboBoxUser.Text, typeof(Auth.BiometricCredentials)
                );
            }
            // сохранить провайдер и максимальное число отпечатков
            this.provider = service.Provider; this.maxFingers = service.GetMaxAvailableFingers(); 

			// создать список для созданных шаблонов
            enrollTemplates = new Dictionary<Bio.Finger, Bio.EnrollTemplate>();
        }
        // инициализировать диалог
		private void OnLoad(object sender, EventArgs e)
		{
			// установить значения пальцев
			checkLeftLittle .Tag = Bio.Finger.LeftLittle; 
			checkLeftRing   .Tag = Bio.Finger.LeftRing;
			checkLeftMiddle .Tag = Bio.Finger.LeftMiddle;
			checkLeftIndex  .Tag = Bio.Finger.LeftIndex;
			checkLeftThumb  .Tag = Bio.Finger.LeftThumb;
			checkRightLittle.Tag = Bio.Finger.RightLittle; 
			checkRightRing  .Tag = Bio.Finger.RightRing;
			checkRightMiddle.Tag = Bio.Finger.RightMiddle;
			checkRightIndex .Tag = Bio.Finger.RightIndex;
			checkRightThumb .Tag = Bio.Finger.RightThumb;

			// для всех считывателей
			foreach (string reader in provider.EnumerateReaders()) 
			{
				// добавить считыватель в список
				comboReader.Items.Add(reader);
			}
			// выбрать считыватель по умолчанию
            if (comboReader.Items.Count > 0) comboReader.SelectedIndex = 0;
             
			// установить значения по умолчанию
            far100.Select(); comboFinger.SelectedIndex = 9;

			// установить начальные условия
			buttonStart.Enabled = (comboFinger.SelectedIndex >= 0); 

			// установить начальные условия
			buttonStop.Enabled = buttonOK.Enabled = false; 

			// запустить таймер 
			timer.Tick += OnTick; timer.Start(); 
		}
		private void OnTick(object sender, EventArgs e)
		{
			// получить идентификатор языка
			CultureInfo cultureInfo = new CultureInfo(
                (int)NativeMethods.GetKeyboardLayout(0).ToInt64() & 0xFFFF
            ); 
			// установить абревиатуру языка
			textBoxLang.Text = cultureInfo.TwoLetterISOLanguageName.ToUpper(); 
		}
        private void OnUserChanged(object sender, EventArgs e)
        {
            // указать отсутствие выбора пальца
            comboFinger.SelectedIndex = -1; 

            // получить биометрический сервис объекта
            Auth.BiometricService service = (Auth.BiometricService)
                obj.GetAuthenticationService(
                    comboBoxUser.Text, typeof(Auth.BiometricCredentials)
            ); 
            // максимальное число отпечатков
            this.maxFingers = service.GetMaxAvailableFingers(); 
        }
        private void OnFingerChanged(object sender, EventArgs e)
        {
			// указать доступность кнопки
			buttonStart.Enabled = (comboFinger.SelectedIndex >= 0); 

            // указать недоступность изображения 
            textInfo.Text = String.Empty; imageFinger.Visible = false; 
        }
        private Bio.Finger GetCurrentFinger(out CheckBox checkBox)
        {
			// указать начальное значение 
			Bio.Finger finger = Bio.Finger.None; checkBox = null; 

			// в зависимости от выбранного индекса
			switch (comboFinger.SelectedIndex)
			{
			// извлечь значение пальца
			case 0: finger = Bio.Finger.LeftLittle ; checkBox = checkLeftLittle ; break;  
			case 1: finger = Bio.Finger.LeftRing   ; checkBox = checkLeftRing   ; break;
			case 2: finger = Bio.Finger.LeftMiddle ; checkBox = checkLeftMiddle ; break;
			case 3: finger = Bio.Finger.LeftIndex  ; checkBox = checkLeftIndex  ; break;
			case 4: finger = Bio.Finger.LeftThumb  ; checkBox = checkLeftThumb  ; break;
			case 5: finger = Bio.Finger.RightLittle; checkBox = checkRightLittle; break;
			case 6: finger = Bio.Finger.RightRing  ; checkBox = checkRightRing  ; break;
			case 7: finger = Bio.Finger.RightMiddle; checkBox = checkRightMiddle; break;
			case 8: finger = Bio.Finger.RightIndex ; checkBox = checkRightIndex ; break;
			case 9: finger = Bio.Finger.RightThumb ; checkBox = checkRightThumb ; break;
			}
            return finger; 
        }
		private void OnCheckClick(object sender, EventArgs e)
		{
			// преобразовать тип объекта
			CheckBox checkBox = (CheckBox)sender;

			// получить идентификатор пальца
			Bio.Finger finger = (Bio.Finger)checkBox.Tag; 

			// удалить шаблон из списка
			enrollTemplates.Remove(finger); checkBox.Enabled = false;  	 
		}
		private void OnPasswordChanged(object sender, EventArgs e)
		{
			// изменить доступность элементов управления
            buttonOK.Enabled = (enrollTemplates.Count > 0) && 
                (textBoxPIN.Text.Length > 0) && (textBoxPIN2.Text.Length > 0); 
		}
        private void OnQualityScroll(object sender, EventArgs e)
        {
            // указать значение качества отпечатка
            labelQualityValue.Text = String.Format("{0} %", trackBarQuality.Value); 
        }
 	    private bool OnCheckImage(Bio.Image image)
		{
            // проверить качество отпечатка
			if (image.Quality >= trackBarQuality.Value) return true; 
            
            // установить текст            
            textInfo.Text = Resource.MessageFingerQuality; return false;
		}
		private void OnStart(object sender, EventArgs e)
		{
            // получить биометрический сервис объекта
            Auth.BiometricService service = (Auth.BiometricService)
                obj.GetAuthenticationService(
                    comboBoxUser.Text, typeof(Auth.BiometricCredentials)
            ); 
			// получить выбранный считыватель
			using (Bio.Reader reader = service.Provider.OpenReader(comboReader.SelectedItem.ToString()))
			try {
			    // вывести сообщение
			    textInfo.Text = Resource.MessageFingerTouch; buttonStop.Enabled = true;

			    // изменить доступность элементов управления
			    buttonStart.Enabled = comboReader.Enabled = comboFinger.Enabled = false; 

                // указать обработчик
                Remoting.IBackgroundHandler handler = 
                    new Remoting.BackgroundHandler(AfterEnroll, null); 

                // запустить поток сканирования
                captureControl = reader.BeginCapture(
                    Bio.ImageTarget.Enroll, OnCheckImage, new TimeSpan(0), handler
                ); 
			}
			// обработать возможную ошибку
			catch (Exception ex) { AfterStop(ex.Message); } 
		}
        // отменить операцию
		private void OnStop(object sender, EventArgs e) 
        { 
            // отменить операцию
            captureControl.Cancel(); captureControl.Dispose(); 
        }
 		private void AfterEnroll(object sender, RunWorkerCompletedEventArgs e)
		{
            // освободить выделенные ресурсы
            captureControl.Dispose();

            // обработать возникшее исключение
            if (e.Error != null) { AfterStop(e.Error.Message); return; } 

            // обработать отмену операции
            if (e.Cancelled) { AfterStop(new OperationCanceledException().Message); return; } 

            // получить биометрический сервис объекта
            Auth.BiometricService service = (Auth.BiometricService)
                obj.GetAuthenticationService(
                    comboBoxUser.Text, typeof(Auth.BiometricCredentials)
            ); 
			// получить выбранный считыватель
			using (Bio.Reader reader = service.Provider.OpenReader(comboReader.SelectedItem.ToString()))
			try { 
                // вывести сообщение о готовности отпечатка
                textInfo.Text = Resource.MessageFingerCaptured; 

                // получить изображение отпечатка
                Bio.Image image = (Bio.Image)e.Result;

				// заполнить текущий отпечаток
				imageFinger.Image = (System.Drawing.Image)
                    image.GetThumbnailImage(imageFinger.Width, imageFinger.Height); 

				// обновить изображение
				imageFinger.Refresh(); imageFinger.Visible = true; int far = 100; 

				// получить значение FAR
				if (far1000    .Checked) far = 1000   ; else
				if (far10000   .Checked) far = 10000  ; else
				if (far100000  .Checked) far = 100000 ; else
				if (far1000000 .Checked) far = 1000000;

				// получить выбранный палец
				CheckBox checkBox; Bio.Finger finger = GetCurrentFinger(out checkBox); 

				// вычислить шаблон для сохранения
				Bio.EnrollTemplate template = provider.CreateEnrollTemplate(finger, image, far); 

				// изменить шаблон в списке
				if (enrollTemplates.ContainsKey(finger)) enrollTemplates[finger] = template;  

				// сохранить шаблон в список
				else enrollTemplates.Add(finger, template); 

                // вывести сообщение о готовности отпечатка
                textInfo.Text = Resource.MessageFingerRepeat; checkBox.Checked = true;

                // указать обработчик
                Remoting.IBackgroundHandler handler = 
                    new Remoting.BackgroundHandler(AfterVerify, null); 

                // запустить поток сканирования
                captureControl = reader.BeginCapture(
                    Bio.ImageTarget.Match, OnCheckImage, new TimeSpan(0), handler
                ); 
			}
			// обработать возможную ошибку
			catch (Exception ex) { AfterStop(ex.Message); }
		} 
 		private void AfterVerify(object sender, RunWorkerCompletedEventArgs e)
		{
            // освободить выделенные ресурсы
            captureControl.Dispose();

            // обработать возникшее исключение
            if (e.Error != null) { AfterStop(e.Error.Message); return; } 

            // обработать отмену операции
            if (e.Cancelled) { AfterStop(new OperationCanceledException().Message); return; } 
            try { 
                // вывести сообщение о готовности отпечатка
                textInfo.Text = Resource.MessageFingerCaptured; 

                // получить изображение отпечатка
                Bio.Image image = (Bio.Image)e.Result;

				// заполнить текущий отпечаток
				imageFinger.Image = (System.Drawing.Image)
                    image.GetThumbnailImage(imageFinger.Width, imageFinger.Height); 

				// обновить изображение
				imageFinger.Refresh(); CheckBox checkBox; 

				// указать начальное значение 
				Bio.Finger finger = GetCurrentFinger(out checkBox); 

                // извлечь шаблон из списка
                Bio.EnrollTemplate template = enrollTemplates[finger]; 

                // проверить корректность отпечатка 
                if (template.Validate(image)) { checkBox.Enabled = true; 
                 
                    // вывести сообщение
                    AfterStop(Resource.MessageFingerEnrollVerified); 
                }
                else {  
                    // удалить шаблон из списка
                    checkBox.Checked = false; enrollTemplates.Remove(finger); 

                    // вывести сообщение
                    AfterStop(Resource.MessageFingerEnrollNoVerified); 
                }
            }
			// обработать возможную ошибку
			catch (Exception ex) { AfterStop(ex.Message); }
        }
		private void AfterStop(string message)
		{
			// указать сообщение
			textInfo.Text = message; buttonStop.Enabled = false; 

			// изменить доступность элементов управления
            comboBoxUser.Enabled = (enrollTemplates.Count == 0); 

			// изменить доступность элементов управления
			groupFar.Enabled = groupSelect.Enabled = true; 

            // указать доступность элемента управления
            buttonStart.Enabled = (enrollTemplates.Count < maxFingers);

            // указать доступность элемента управления
			comboReader.Enabled = comboFinger.Enabled = buttonStart.Enabled; 

			// изменить доступность элементов управления
            buttonOK.Enabled = (enrollTemplates.Count > 0) && (textBoxPIN.Text.Length > 0); 
		} 
        private void OnButtonOK(object sender, EventArgs e)
        {
            // отменить закрытие диалога
            DialogResult = DialogResult.None; 

            // проверить совпадение паролей
            if (textBoxPIN.Text != textBoxPIN2.Text)
            {
    	        // вывести описание ошибки
		        MessageBox.Show(this, Resource.ErrorPasswordMismatch, 
                    Text, MessageBoxButtons.OK, MessageBoxIcon.Error); 
                
                // установить фокус на элемент
                textBoxPIN.Focus(); return; 
            }
            // указать закрытие диалога
            else DialogResult = DialogResult.OK; 
        }
		// считанные отпечатки
		public Bio.EnrollTemplate[] EnrollTemplates { get 
        { 
            // скопировать шаблоны в список
            return new List<Bio.EnrollTemplate>(enrollTemplates.Values).ToArray(); 
        }}
        // введенный пин-код        
        public string PinCode { get { return textBoxPIN.Text; }}
    }
}
