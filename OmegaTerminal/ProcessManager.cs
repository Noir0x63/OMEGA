using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace OmegaTerminal
{
    public class ProcessManager
    {
        private Process? _nodeProcess;
        private Job? _job;
        private bool _isStopping = false;

        public event Action<int, string>? ProgressChanged;
        public event Action<string>? OnionAddressDetected;
        public event Action<string>? AdminRouteDetected;
        public event Action<string>? LogReceived;
        public event Action<int>? ProcessExited;

        public bool IsRunning => _nodeProcess != null && !_nodeProcess.HasExited;

        public string GetResourcesDirectory()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string resourcesDir = Path.Combine(baseDir, "Resources");
            if (!Directory.Exists(resourcesDir))
            {
                // Fallback to local source resources if in debug/test env
                string localDir = Path.Combine(Directory.GetParent(baseDir)?.Parent?.Parent?.FullName ?? "", "Resources");
                if (Directory.Exists(localDir))
                {
                    resourcesDir = localDir;
                }
            }
            return resourcesDir;
        }

        public bool HasKeys()
        {
            string dir = GetResourcesDirectory();
            return File.Exists(Path.Combine(dir, "master_public.pem")) &&
                   File.Exists(Path.Combine(dir, "master_private.enc")) &&
                   File.Exists(Path.Combine(dir, "server_secrets.enc"));
        }

        public async Task<bool> GenerateIdentityAsync(string passphrase)
        {
            string resourcesDir = GetResourcesDirectory();
            string nodePath = Path.Combine(resourcesDir, "node.exe");
            string keygenPath = "keygen.js";

            if (!File.Exists(nodePath))
            {
                throw new FileNotFoundException("El ejecutable portátil node.exe no se encontró.", nodePath);
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = nodePath,
                Arguments = $"\"{keygenPath}\"",
                WorkingDirectory = resourcesDir,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var process = new Process { StartInfo = startInfo };
            
            process.OutputDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    LogReceived?.Invoke(StripAnsi(e.Data));
                }
            };
            process.ErrorDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    LogReceived?.Invoke("[Error Keygen] " + StripAnsi(e.Data));
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            // Write passphrase twice (enter, then confirm) to standard input
            using (var writer = new StreamWriter(process.StandardInput.BaseStream, new UTF8Encoding(false)))
            {
                await writer.WriteLineAsync(passphrase);
                await writer.FlushAsync();
                await Task.Delay(500);
                await writer.WriteLineAsync(passphrase);
                await writer.FlushAsync();
            }

            await process.WaitForExitAsync();
            return process.ExitCode == 0;
        }

        public void Start()
        {
            if (IsRunning) return;
            _isStopping = false;

            string resourcesDir = GetResourcesDirectory();
            string nodePath = Path.Combine(resourcesDir, "node.exe");
            string launcherPath = "launcher.js";

            if (!File.Exists(nodePath))
            {
                throw new FileNotFoundException("El ejecutable portátil node.exe no se encontró en la carpeta de recursos.", nodePath);
            }

            if (!File.Exists(Path.Combine(resourcesDir, launcherPath)))
            {
                throw new FileNotFoundException("El script launcher.js no se encontró.", Path.Combine(resourcesDir, launcherPath));
            }

            // Create Job Object to manage clean recursive teardown of node + tor
            try
            {
                _job = new Job();
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke($"[C# Job Object Warning] {ex.Message}. Se usará desactivación recursiva estándar.");
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = nodePath,
                Arguments = $"\"{launcherPath}\"",
                WorkingDirectory = resourcesDir,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            _nodeProcess = new Process { StartInfo = startInfo, EnableRaisingEvents = true };

            _nodeProcess.OutputDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    ParseLine(e.Data);
                }
            };

            _nodeProcess.ErrorDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    LogReceived?.Invoke($"[Error Launcher] {StripAnsi(e.Data)}");
                }
            };

            _nodeProcess.Exited += (sender, e) =>
            {
                if (!_isStopping)
                {
                    ProcessExited?.Invoke(_nodeProcess.ExitCode);
                }
            };

            _nodeProcess.Start();

            if (_job != null)
            {
                try
                {
                    _job.AddProcess(_nodeProcess.Handle);
                }
                catch (Exception ex)
                {
                    LogReceived?.Invoke($"[C# Job Object Association Failed] {ex.Message}");
                }
            }

            _nodeProcess.BeginOutputReadLine();
            _nodeProcess.BeginErrorReadLine();
        }

        private string StripAnsi(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;
            return Regex.Replace(input, @"\x1B\[[0-9;]*[a-zA-Z]", "");
        }

        private void ParseLine(string rawLine)
        {
            string line = StripAnsi(rawLine).Trim();
            if (string.IsNullOrEmpty(line)) return;

            LogReceived?.Invoke(line);

            // 1. Progress match: e.g. [██████░░░] 80% Connecting...
            var progressMatch = Regex.Match(line, @"(\d+)%");
            if (progressMatch.Success)
            {
                int percent = int.Parse(progressMatch.Groups[1].Value);
                string status = "Estableciendo circuitos...";
                
                int percentIndex = line.IndexOf('%');
                if (percentIndex != -1 && percentIndex + 1 < line.Length)
                {
                    status = line.Substring(percentIndex + 1).Trim();
                }
                ProgressChanged?.Invoke(percent, status);
            }

            // 2. Admin route match: [ADMIN] Active route: /5f3a9e...
            if (line.Contains("[ADMIN] Active route:"))
            {
                var routeMatch = Regex.Match(line, @"Active route:\s*/([a-f0-9]+)");
                if (routeMatch.Success)
                {
                    AdminRouteDetected?.Invoke(routeMatch.Groups[1].Value);
                }
            }

            // 3. Onion address match: ONION: abcdef.onion
            if (line.Contains("ONION:"))
            {
                var onionMatch = Regex.Match(line, @"ONION:\s*([a-z2-7]{56}\.onion)", RegexOptions.IgnoreCase);
                if (onionMatch.Success)
                {
                    OnionAddressDetected?.Invoke(onionMatch.Groups[1].Value);
                }
            }
        }

        public void Stop()
        {
            if (_nodeProcess == null) return;
            _isStopping = true;

            try
            {
                if (!_nodeProcess.HasExited)
                {
                    _nodeProcess.Kill(entireProcessTree: true);
                }
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke($"[Stop Error] {ex.Message}");
            }
            finally
            {
                _nodeProcess.Dispose();
                _nodeProcess = null;

                if (_job != null)
                {
                    _job.Dispose();
                    _job = null;
                }
            }
        }
    }
}
