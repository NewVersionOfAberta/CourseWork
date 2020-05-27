namespace WindowsSniffer
{
    partial class fmSniffer
    {
        /// <summary>
        /// Обязательная переменная конструктора.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Освободить все используемые ресурсы.
        /// </summary>
        /// <param name="disposing">истинно, если управляемый ресурс должен быть удален; иначе ложно.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Код, автоматически созданный конструктором форм Windows

        /// <summary>
        /// Требуемый метод для поддержки конструктора — не изменяйте 
        /// содержимое этого метода с помощью редактора кода.
        /// </summary>
        private void InitializeComponent()
        {
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle2 = new System.Windows.Forms.DataGridViewCellStyle();
            this.btnProccess = new System.Windows.Forms.Button();
            this.lvPackets = new System.Windows.Forms.ListView();
            this.columnHeader1 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.cbIP = new System.Windows.Forms.ComboBox();
            this.cbProtocol = new System.Windows.Forms.ComboBox();
            this.dgvExtPacket = new System.Windows.Forms.DataGridView();
            this.cItemName = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.cValue = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.cDescribe = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.rtbData = new System.Windows.Forms.RichTextBox();
            ((System.ComponentModel.ISupportInitialize)(this.dgvExtPacket)).BeginInit();
            this.SuspendLayout();
            // 
            // btnProccess
            // 
            this.btnProccess.Location = new System.Drawing.Point(508, 12);
            this.btnProccess.Name = "btnProccess";
            this.btnProccess.Size = new System.Drawing.Size(84, 24);
            this.btnProccess.TabIndex = 0;
            this.btnProccess.Text = "Начать";
            this.btnProccess.UseVisualStyleBackColor = true;
            this.btnProccess.Click += new System.EventHandler(this.btnProccess_Click);
            // 
            // lvPackets
            // 
            this.lvPackets.BackColor = System.Drawing.SystemColors.InactiveCaptionText;
            this.lvPackets.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader1});
            this.lvPackets.ForeColor = System.Drawing.SystemColors.Menu;
            this.lvPackets.FullRowSelect = true;
            this.lvPackets.GridLines = true;
            this.lvPackets.HideSelection = false;
            this.lvPackets.Location = new System.Drawing.Point(12, 40);
            this.lvPackets.MultiSelect = false;
            this.lvPackets.Name = "lvPackets";
            this.lvPackets.Size = new System.Drawing.Size(900, 901);
            this.lvPackets.TabIndex = 2;
            this.lvPackets.UseCompatibleStateImageBehavior = false;
            this.lvPackets.View = System.Windows.Forms.View.Details;
            this.lvPackets.SelectedIndexChanged += new System.EventHandler(this.lvPackets_SelectedIndexChanged);
            // 
            // columnHeader1
            // 
            this.columnHeader1.Text = "Пакеты:";
            this.columnHeader1.Width = 860;
            // 
            // cbIP
            // 
            this.cbIP.FormattingEnabled = true;
            this.cbIP.Location = new System.Drawing.Point(13, 12);
            this.cbIP.Name = "cbIP";
            this.cbIP.Size = new System.Drawing.Size(256, 24);
            this.cbIP.TabIndex = 4;
            // 
            // cbProtocol
            // 
            this.cbProtocol.FormattingEnabled = true;
            this.cbProtocol.Location = new System.Drawing.Point(275, 12);
            this.cbProtocol.Name = "cbProtocol";
            this.cbProtocol.Size = new System.Drawing.Size(227, 24);
            this.cbProtocol.TabIndex = 5;
            this.cbProtocol.SelectedIndexChanged += new System.EventHandler(this.cbProtocol_SelectedIndexChanged);
            // 
            // dgvExtPacket
            // 
            this.dgvExtPacket.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dgvExtPacket.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.cItemName,
            this.cValue,
            this.cDescribe});
            dataGridViewCellStyle2.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle2.BackColor = System.Drawing.SystemColors.Window;
            dataGridViewCellStyle2.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            dataGridViewCellStyle2.ForeColor = System.Drawing.SystemColors.ControlText;
            dataGridViewCellStyle2.SelectionBackColor = System.Drawing.SystemColors.Highlight;
            dataGridViewCellStyle2.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle2.WrapMode = System.Windows.Forms.DataGridViewTriState.True;
            this.dgvExtPacket.DefaultCellStyle = dataGridViewCellStyle2;
            this.dgvExtPacket.Location = new System.Drawing.Point(918, 40);
            this.dgvExtPacket.Name = "dgvExtPacket";
            this.dgvExtPacket.RowHeadersVisible = false;
            this.dgvExtPacket.RowHeadersWidth = 10;
            this.dgvExtPacket.RowTemplate.Height = 35;
            this.dgvExtPacket.Size = new System.Drawing.Size(1000, 732);
            this.dgvExtPacket.TabIndex = 6;
            // 
            // cItemName
            // 
            this.cItemName.Frozen = true;
            this.cItemName.HeaderText = "Элемент";
            this.cItemName.MinimumWidth = 6;
            this.cItemName.Name = "cItemName";
            this.cItemName.ReadOnly = true;
            this.cItemName.Width = 125;
            // 
            // cValue
            // 
            this.cValue.Frozen = true;
            this.cValue.HeaderText = "Значение";
            this.cValue.MinimumWidth = 6;
            this.cValue.Name = "cValue";
            this.cValue.ReadOnly = true;
            this.cValue.Width = 125;
            // 
            // cDescribe
            // 
            this.cDescribe.HeaderText = "Описание";
            this.cDescribe.MinimumWidth = 6;
            this.cDescribe.Name = "cDescribe";
            this.cDescribe.ReadOnly = true;
            this.cDescribe.Width = 500;
            // 
            // rtbData
            // 
            this.rtbData.Location = new System.Drawing.Point(918, 778);
            this.rtbData.Name = "rtbData";
            this.rtbData.Size = new System.Drawing.Size(970, 163);
            this.rtbData.TabIndex = 7;
            this.rtbData.Text = "";
            // 
            // fmSniffer
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1900, 953);
            this.Controls.Add(this.rtbData);
            this.Controls.Add(this.dgvExtPacket);
            this.Controls.Add(this.cbProtocol);
            this.Controls.Add(this.cbIP);
            this.Controls.Add(this.lvPackets);
            this.Controls.Add(this.btnProccess);
            this.Name = "fmSniffer";
            this.Text = "Sniffer";
            this.WindowState = System.Windows.Forms.FormWindowState.Maximized;
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.fmSniffer_FormClosing);
            this.Load += new System.EventHandler(this.fmSniffer_Load);
            ((System.ComponentModel.ISupportInitialize)(this.dgvExtPacket)).EndInit();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button btnProccess;
        private System.Windows.Forms.ListView lvPackets;
        private System.Windows.Forms.ComboBox cbIP;
        private System.Windows.Forms.ComboBox cbProtocol;
        private System.Windows.Forms.DataGridView dgvExtPacket;
        private System.Windows.Forms.ColumnHeader columnHeader1;
        private System.Windows.Forms.DataGridViewTextBoxColumn cItemName;
        private System.Windows.Forms.DataGridViewTextBoxColumn cValue;
        private System.Windows.Forms.DataGridViewTextBoxColumn cDescribe;
        private System.Windows.Forms.RichTextBox rtbData;
    }
}

