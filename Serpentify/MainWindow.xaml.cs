using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Collections.ObjectModel;

namespace Serpentify
{

    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            CryptState = States.Encrypt;
            KeySize = KeySizes._128;
            inputBox.Text = "HTL-Ottakring";
            keyBox.Text = "schlusselschlusselschlusselschlu";
        }

        CSerpent Serpent;

        #region Variablen
        Random r = new Random();

        private States CryptState;
        private enum States
        {
            Encrypt,
            Decrypt
        };

        private KeySizes KeySize;
        private enum KeySizes : int
        { 
            _128 = 128,
            _192 = 192,
            _256 = 256
        };

        bool randomKey = false;
        #endregion

        #region Methoden
        private void Encrypt() {

            string output = "";

            #region Check
            if ((keyBox.Text.Length * 4 != (int)KeySize)) {
                MessageBox.Show("Keysize doesnt match.");
                return;
            }

            if(String.IsNullOrEmpty(inputBox.Text)){
                MessageBox.Show("Input Field is empty.");
                return;
            }

            if (String.IsNullOrEmpty(keyBox.Text))
                randomKey = true;
            else
                randomKey = false;

            Serpent = new CSerpent();


            #endregion

            string inp = ConvertTextToHex(inputBox.Text);
            string key = ConvertTextToHex(keyBox.Text);
            
            string plain = inp.Length % 32 == 0 ? inp : inp.PadRight((inp.Length / 32 + 1) * 32, '0');

            /* blockwise encryption */
            for (int i = 0; i < plain.Length; i += 32)
            {
                if (StringToHex(plain.Substring(i, 32)) == null || StringToHex(key) == null)
                {
                    MessageBox.Show("Invalid hex value!");
                    return;
                }
                output += HexToString(Serpent.Encrypt(StringToHex(plain.Substring(i, 32)), StringToHex(key)));
            }

            SListView.Collection.Add(
                new SListView("Enc",inputBox.Text,keyBox.Text,ConvertHexToText(output)));
            DGAnz.ItemsSource = SListView.Collection;
            
        }

        private void Decrypt() {
            string output = "";

            #region Check
            if ((keyBox.Text.Length * 4 != (int)KeySize))
            {
                MessageBox.Show("Keysize doesnt match.");
                return;
            }

            if (String.IsNullOrEmpty(inputBox.Text))
            {
                MessageBox.Show("Input Field is empty.");
                return;
            }

            if (String.IsNullOrEmpty(keyBox.Text))
                randomKey = true;
            else
                randomKey = false;

            Serpent = new CSerpent();


            #endregion

            Serpent = new CSerpent();

            string inp = ConvertTextToHex(inputBox.Text);
            string key = ConvertTextToHex(keyBox.Text);

            /* adding a 0, if the string is not dividable by 32 */
            string cipher = inp.Length % 32 == 0 ? inp : inp.PadRight((inputBox.Text.Length / 32 + 1) * 32, '0');

            /* blockwise decryption */
            for (int i = 0; i < cipher.Length; i = i + 32)
            {
                if (StringToHex(cipher.Substring(i, 32)) == null || StringToHex(key) == null)
                {
                    MessageBox.Show("Invalid hex value!");
                    return;
                }
                output += HexToString(Serpent.Decrypt(StringToHex(cipher.Substring(i, 32)), StringToHex(key)));
            }
            
            //output = output.Replace("00","");
            SListView.Collection.Add(
                new SListView("Dec", inputBox.Text, keyBox.Text, ConvertHexToText(output)));
            DGAnz.ItemsSource = SListView.Collection;
        }

        // Überprüfen der Eingaben
        private void KeyCheck() {
            int length = (keyBox.Text.Length * 4);
            keySizelbl.Content = String.Format("KeySize: {0} Bits", length);
            if (length == (int)KeySize)
                keySizelbl.Foreground = Brushes.Green;
            else
                keySizelbl.Foreground = Brushes.Red;
        }


        public string ConvertTextToHex(string asciiString)
        {
            string hex = "";
            foreach (char c in asciiString)
            {
                int tmp = c;
                hex += String.Format("{0:x2}", (uint)System.Convert.ToUInt32(tmp.ToString()));
            }
            return hex;
        }

        public string ConvertHexToText(string HexValue)
        {
            string StrValue = "";
            while (HexValue.Length > 0)
            {
                StrValue += System.Convert.ToChar(System.Convert.ToUInt32(HexValue.Substring(0, 2), 16)).ToString();
                HexValue = HexValue.Substring(2, HexValue.Length - 2);
            }
            return StrValue;
        }


        #region Konvertierung
        /* converts a string to hexvalues which are written to a uint[] */
        private uint[] StringToHex(string value)
        {
            uint[] num = new uint[value.Length / 8];
            int num1 = 0;
            while (true)
            {
                if ((num1 >= num.Length ? true : value.Length < 8))
                    break;
                try
                {
                    num[num1] = Convert.ToUInt32(value.Substring(0, Math.Min(value.Length, 8)).PadRight(8, '0'), 16);
                }
                catch
                {
                    return null;
                }
                value = value.Substring(8);
                num1++;
            }
            return num;
        }

        /* convert hexvalues (uint[]) to a string */
        private string HexToString(uint[] value)
        {
            string str = "";
            uint[] numArray = value;
            for (int i = 0; i < numArray.Length; i++)
            {
                uint num = numArray[i];
                str = string.Concat(str, num.ToString("X").PadLeft(8, '0'));
            }
            return str;
        }
        #endregion

        #endregion

        #region Event Handler

        // Menü
        private void Men_About_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("About");
        }
        private void Men_Exit_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        // Buttons
        private void actionBtn_Click(object sender, RoutedEventArgs e)
        {
            switch (radio_enc.IsChecked) { 
                case true:
                    Encrypt();
                break;

                case false:
                    Decrypt();
                break;
            }
        }
        private void btn_Cancel_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
 
        // Radio Buttons - Encrypt/Decrypt Modus
        private void radio_dec_Checked(object sender, RoutedEventArgs e)
        {
            actionBtn.Content = "Decrypt";
            CryptState = States.Decrypt;
        }
        private void radio_enc_Checked(object sender, RoutedEventArgs e)
        {
            actionBtn.Content = "Encrypt";
            CryptState = States.Encrypt;
        }

        // Radio Buttons - Keysize
        private void rad128_Checked(object sender, RoutedEventArgs e)
        {
            KeySize = KeySizes._128;
            KeyCheck();
        }
        private void rad192_Checked(object sender, RoutedEventArgs e)
        {
            KeySize = KeySizes._192;
            KeyCheck();
        }
        private void rad256_Checked(object sender, RoutedEventArgs e)
        {
            KeySize = KeySizes._256;
            KeyCheck();
        }
       

        private void keyBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            KeyCheck();
        }
        #endregion
    }

    // Klasse für die Anzeige (DataGrid)
    class SListView {

        public static ObservableCollection<SListView> Collection = new ObservableCollection<SListView>();
        public string Mode{get;set;} 
        public string Input{get;set;} 
        public string Key{get;set;}
        public string Output { get; set; }

        public SListView(string Mode, string Input, string Key, string Output)
        {
            this.Input = Input;
            this.Key = Key;
            this.Mode = Mode;
            this.Output = Output;
        }

    }


}
