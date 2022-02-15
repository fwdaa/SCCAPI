using System; 
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог выбора параметров ключа
	///////////////////////////////////////////////////////////////////////////
	public partial class ParametersDialog : Form
	{
        // выбрать параметры ключа
        public static IParameters Show(IWin32Window parent, ParametersControl control)
        {
            // создать диалог
            ParametersDialog dialog = new ParametersDialog(control); 

            // отобразить диалог
            DialogResult result = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// проверить результат диалога
			return (result == DialogResult.OK) ? dialog.Parameters : null;
        }
		// конструктор
		public ParametersDialog(ParametersControl control) 
        { 
            // сохранить переданные параметры
            InitializeComponent(); this.control = control; 
        }
		// конструктор
		public ParametersDialog() { InitializeComponent(); } 
        
        // выбранные параметры ключа
        public IParameters Parameters { get { return parameters; } }   

        // элемент управления и выбранные параметры
        private ParametersControl control; private IParameters parameters;

		///////////////////////////////////////////////////////////////////////
		// События 
		///////////////////////////////////////////////////////////////////////
		private void OnLoad(object sender, System.EventArgs e)
		{
			// указать параметры элемента управления
			control.Padding = panel.Padding; control.Size = panel.Size;	 

			// указать параметры элемента управления
            control.Location = panel.Location; Controls.Add(control); 
		}
        private void OnSelect(object sender, EventArgs e)
        {
			// выбрать параметры ключа
			parameters = control.GetParameters(); 
        }
	}
}
