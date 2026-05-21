using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Media;

namespace OmegaTerminal
{
    public partial class MainWindow : Window
    {
        private readonly ProcessManager _processManager;
        private string? _onionAddress;
        private string? _adminRoute;

        public MainWindow()
        {
            InitializeComponent();
            _processManager = new ProcessManager();

            // Hook process manager events
            _processManager.ProgressChanged += OnProgressChanged;
            _processManager.OnionAddressDetected += OnOnionAddressDetected;
            _processManager.AdminRouteDetected += OnAdminRouteDetected;
            _processManager.LogReceived += OnLogReceived;
            _processManager.ProcessExited += OnProcessExited;

            // Hook window lifetime events
            Loaded += MainWindow_Loaded;
            Closing += MainWindow_Closing;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_processManager.HasKeys())
                {
                    // Keys exist, go straight to boot screen
                    LoadingPanel.Visibility = Visibility.Visible;
                    SetupPanel.Visibility = Visibility.Collapsed;
                    _processManager.Start();
                }
                else
                {
                    // No keys, show master passphrase setup screen
                    SetupPanel.Visibility = Visibility.Visible;
                    LoadingPanel.Visibility = Visibility.Collapsed;
                    LogTextBox.AppendText("[SISTEMA] No se detectó identidad activa. Por favor, crea una frase de contraseña maestra para inicializar el Protocolo OMEGA." + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Error de Inicialización:\n{ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
                Close();
            }
        }

        private async void BtnGenerateIdentity_Click(object sender, RoutedEventArgs e)
        {
            string passphrase = TxtPassphrase.Password;
            string confirm = TxtConfirmPassphrase.Password;

            if (string.IsNullOrEmpty(passphrase) || passphrase.Length < 12)
            {
                MessageBox.Show(
                    "La frase de contraseña maestra debe tener al menos 12 caracteres por motivos de seguridad criptográfica.",
                    "Contraseña muy corta",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
                return;
            }

            if (passphrase != confirm)
            {
                MessageBox.Show(
                    "Las contraseñas ingresadas no coinciden. Por favor, verifícalas.",
                    "Contraseñas no coinciden",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
                return;
            }

            // Lock UI controls
            TxtPassphrase.IsEnabled = false;
            TxtConfirmPassphrase.IsEnabled = false;
            BtnGenerateIdentity.IsEnabled = false;
            BtnGenerateIdentity.Content = "Generando Llaves RSA-4096 (PBKDF2 600K)...";

            try
            {
                LogTextBox.AppendText("[KEYGEN] Iniciando generación de llaves criptográficas..." + Environment.NewLine);
                bool success = await _processManager.GenerateIdentityAsync(passphrase);

                if (success)
                {
                    LogTextBox.AppendText("[KEYGEN] ✓ Credenciales generadas con éxito y almacenadas de forma cifrada (AES-256-GCM)." + Environment.NewLine);
                    
                    // Transition panels
                    SetupPanel.Visibility = Visibility.Collapsed;
                    LoadingPanel.Visibility = Visibility.Visible;

                    // Start process manager for booting Tor / Server
                    _processManager.Start();
                }
                else
                {
                    throw new Exception("El proceso de generación de llaves devolvió un código de error.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Error al generar credenciales:\n{ex.Message}",
                    "Error de Cifrado",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );

                // Unlock UI controls
                TxtPassphrase.IsEnabled = true;
                TxtConfirmPassphrase.IsEnabled = true;
                BtnGenerateIdentity.IsEnabled = true;
                BtnGenerateIdentity.Content = "Generar Credenciales y Activar Relay";
            }
        }

        private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            _processManager.Stop();
        }

        private void OnProgressChanged(int percent, string status)
        {
            Dispatcher.Invoke(() =>
            {
                LauncherProgressBar.Value = percent;
                LoadingPercentText.Text = $"{percent}%";
                LoadingStatus.Text = status;
            });
        }

        private void OnOnionAddressDetected(string address)
        {
            Dispatcher.Invoke(() =>
            {
                _onionAddress = address;
                OnionAddressBox.Text = address;
                CheckTransition();
            });
        }

        private void OnAdminRouteDetected(string route)
        {
            Dispatcher.Invoke(() =>
            {
                _adminRoute = route;
                AdminPathText.Text = $"/{route}";
                CheckTransition();
            });
        }

        private void CheckTransition()
        {
            if (!string.IsNullOrEmpty(_onionAddress) && !string.IsNullOrEmpty(_adminRoute))
            {
                LoadingPanel.Visibility = Visibility.Collapsed;
                ControlPanel.Visibility = Visibility.Visible;
                StatusDot.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981"));
                StatusBadgeText.Text = "ACTIVO - RED TOR";
            }
        }

        private void OnLogReceived(string log)
        {
            Dispatcher.Invoke(() =>
            {
                LogTextBox.AppendText(log + Environment.NewLine);
                LogScrollViewer.ScrollToEnd();
            });
        }

        private void OnProcessExited(int exitCode)
        {
            Dispatcher.Invoke(() =>
            {
                StatusDot.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                StatusBadgeText.Text = "DESCONECTADO";
                LogTextBox.AppendText($"[SISTEMA] El proceso de backend terminó inesperadamente con código de salida: {exitCode}." + Environment.NewLine);
                LogScrollViewer.ScrollToEnd();
            });
        }

        private void BtnCopyOnion_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(_onionAddress))
            {
                try
                {
                    Clipboard.SetText(_onionAddress);
                    BtnCopyOnion.Content = "¡Dirección Copiada!";
                    var timer = new System.Windows.Threading.DispatcherTimer
                    {
                        Interval = TimeSpan.FromSeconds(2)
                    };
                    timer.Tick += (s, ev) =>
                    {
                        BtnCopyOnion.Content = "Copiar Dirección";
                        timer.Stop();
                    };
                    timer.Start();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error al copiar al portapapeles: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }

        private void BtnOpenAdmin_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(_onionAddress) && !string.IsNullOrEmpty(_adminRoute))
            {
                string fullUrl = $"http://{_onionAddress}/{_adminRoute}";
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = fullUrl,
                        UseShellExecute = true
                    };
                    Process.Start(psi);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        $"No se pudo abrir el navegador automáticamente:\n{ex.Message}\n\nEnlace: {fullUrl}",
                        "Error al abrir enlace",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning
                    );
                }
            }
        }
    }
}