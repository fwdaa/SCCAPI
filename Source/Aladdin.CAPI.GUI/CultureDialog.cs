using System; 
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог выбора криптографической культуры
	///////////////////////////////////////////////////////////////////////////
	public partial class CultureDialog : Form
	{
        // выбрать криптографическую культуру
        public static PBE.PBECulture Show(IWin32Window parent, CultureControl[] controls)
        {
            // создать диалог
            CultureDialog dialog = new CultureDialog(controls); 

            // отобразить диалог
            DialogResult result = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// проверить результат диалога
			return (result == DialogResult.OK) ? dialog.Culture : null;
        }
		// конструктор
		public CultureDialog(params CultureControl[] controls) 
        { 
            // сохранить переданные параметры
            InitializeComponent(); 

			// для всех закладок
			foreach (CultureControl control in controls)
			{
				// добавить страницу закладок
				tabControl.TabPages.Add(CreateTabPage(tabTemplate, control));
 			}
			// удалить фиктивную страницу
			tabControl.TabPages.Remove(tabTemplate);

			// проверить наличие закладок 
			if (tabControl.TabPages.Count == 0) throw new NotFoundException(); 
        }
		// конструктор
		public CultureDialog() { InitializeComponent(); } 

        // выбранная криптографическая культура
        public PBE.PBECulture Culture { get { return culture; } } private PBE.PBECulture culture;   

		///////////////////////////////////////////////////////////////////////
		// События 
		///////////////////////////////////////////////////////////////////////
		private void OnLoad(object sender, System.EventArgs e)
		{
		}
		private TabPage CreateTabPage(TabPage template, CultureControl control)
		{
			// указать провайдер для страницы
			TabPage tabPage = new TabPage(); tabPage.Location = template.Location; 

			// указать параметры визуальной страницы
			tabPage.Padding = template.Padding; tabPage.Size = template.Size;	 

			// связать страницу с представлением 
			tabPage.Text = control.Type; tabPage.Controls.Add(control); return tabPage; 
		}
        private void OnSelect(object sender, EventArgs e)
        {
			// получить активную закладку
			TabPage tabPage = tabControl.TabPages[tabControl.SelectedIndex]; 

			// выбрать криптографическую культуру
			culture = ((CultureControl)tabPage.Controls[0]).GetCulture(); 
        }
	}
}
