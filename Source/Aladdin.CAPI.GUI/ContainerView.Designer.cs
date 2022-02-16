﻿namespace Aladdin.CAPI.GUI
{
	partial class ContainerView
	{
		/// <summary> 
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.IContainer components = null;

		/// <summary> 
		/// Clean up any resources being used.
		/// </summary>
		/// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing && (components != null))
			{
				components.Dispose();
			}
			base.Dispose(disposing);
		}

		#region Component Designer generated code

		/// <summary> 
		/// Required method for Designer support - do not modify 
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ContainerView));
            this.listView = new System.Windows.Forms.ListView();
            this.columnSubject = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnNotBefore = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnNotAfter = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnKeyUsage = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.SuspendLayout();
            // 
            // listView
            // 
            resources.ApplyResources(this.listView, "listView");
            this.listView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnSubject,
            this.columnNotBefore,
            this.columnNotAfter,
            this.columnKeyUsage});
            this.listView.FullRowSelect = true;
            this.listView.GridLines = true;
            this.listView.MultiSelect = false;
            this.listView.Name = "listView";
            this.listView.ShowItemToolTips = true;
            this.listView.UseCompatibleStateImageBehavior = false;
            this.listView.View = System.Windows.Forms.View.Details;
            this.listView.SelectedIndexChanged += new System.EventHandler(this.OnSelectedIndexChanged);
            this.listView.DoubleClick += new System.EventHandler(this.OnDoubleClick);
            // 
            // columnSubject
            // 
            resources.ApplyResources(this.columnSubject, "columnSubject");
            // 
            // columnNotBefore
            // 
            resources.ApplyResources(this.columnNotBefore, "columnNotBefore");
            // 
            // columnNotAfter
            // 
            resources.ApplyResources(this.columnNotAfter, "columnNotAfter");
            // 
            // columnKeyUsage
            // 
            resources.ApplyResources(this.columnKeyUsage, "columnKeyUsage");
            // 
            // ContainerView
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.listView);
            this.Name = "ContainerView";
            this.ResumeLayout(false);

		}

		#endregion

		private System.Windows.Forms.ListView listView;
		private System.Windows.Forms.ColumnHeader columnKeyUsage;
		private System.Windows.Forms.ColumnHeader columnSubject;
		private System.Windows.Forms.ColumnHeader columnNotBefore;
		private System.Windows.Forms.ColumnHeader columnNotAfter;
	}
}