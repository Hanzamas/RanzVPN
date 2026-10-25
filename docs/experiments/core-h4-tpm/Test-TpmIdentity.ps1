# Test-TpmIdentity.ps1
#
# CORE-H4 (#401): the experiments behind ADR-0041, which asks whether the identity of a Node should be
# bound to a TPM. The script is a tool for a person with a TPM. It is no part of any shipped binary and
# no job of CI needs a TPM to run it: on a host without one it runs the software controls and records
# what the host says about the missing TPM.
#
# What it does, on any Windows 10 or 11, or Windows Server 2016 or later, as a standard user:
#   E1  describes the host: the OS, the architecture, the TPM that the TPM Base Services report
#   E2  opens the Microsoft Platform Crypto Provider (the TPM) and the Microsoft Software Key Storage
#       Provider (the control), and records the error of the one that does not open
#   E3  creates one key of each kind that the ADR discusses in each provider, signs or agrees with it, and
#       records which kinds the provider refuses: ECDSA and ECDH on P-256, P-384 and P-521, ECDH on
#       curve25519 (the key of the Noise static key), RSA (with -IncludeRsa: 2048, 3072 and 4096 bits)
#   E4  times the ECDSA P-256 signature and the ECDH P-256 agreement of each provider one after another,
#       and then from several threads at once, to see what a busy TPM does
#   E5  runs a TLS handshake over the loopback with Schannel, with no client certificate, with a client
#       certificate whose key is in the software provider, and with one whose key is in the TPM, and
#       times each; one more handshake presents a certificate that the server does not pin
# With -Machine, in an elevated process:
#   E6  makes a key in the machine key set, as the installer of a Node would, and lets a service that runs
#       as a virtual account (the account type of the Node service, ADR-0039) open it and sign, make a
#       key in the machine key set, and make a key in its own key set (what the Node service does). The
#       service is a small program of C# that the script builds with csc.exe of the .NET Framework 4,
#       runs, and deletes; it says where the file of each key it made is and who may read it
# With -ReadEk, in an elevated process:
#   E7  reads the endorsement key of the TPM and the certificates of its manufacturer, and builds the chain
#       of the certificate, as the Controller would have to
# What it never does: clear the TPM, change its owner, lockout or authorization values, or send a wrong
# authorization value. Without -Machine and -ReadEk it needs no rights and touches only the key set of the
# current user. Every key that it creates has a random name that starts with ranz-h4- and is deleted at the
# end. The output of -ReadEk names the device: do not post it.
#
# Usage (Windows PowerShell 5.1 or PowerShell 7):
#   powershell -NoProfile -ExecutionPolicy Bypass -File Test-TpmIdentity.ps1 -OutDir out
#   -SignCount 50       signatures per timing run
#   -Threads 4          threads of the busy run
#   -HandshakeCount 20  TLS handshakes per run
#   -IncludeRsa         also RSA 2048, 3072 and 4096 (a TPM needs seconds to make an RSA key)
#   -SkipTls            leave E5 out
#   -NoTpm              leave every use of the TPM out and run the controls only
#   -Machine            run E6 (elevated; it builds, runs and deletes a service named RanzH4Probe)
#   -ReadEk             run E7 (elevated)
# TLS 1.3 needs PowerShell 7 on Windows 11 or Windows Server 2022 or later. Windows PowerShell 5.1 runs
# E5 over TLS 1.2: the client signs the handshake once in both, so the cost of the TPM is the same.
# It writes results.json and report.txt to -OutDir and prints the report. The exit code is 0 when the
# script ran to its end, whatever the experiments found.

[CmdletBinding()]
param(
	[string] $OutDir = (Join-Path (Get-Location).Path 'tpm-experiment-out'),
	[int] $SignCount = 50,
	[int] $Threads = 4,
	[int] $HandshakeCount = 20,
	[switch] $IncludeRsa,
	[switch] $SkipTls,
	[switch] $NoTpm,
	[switch] $Machine,
	[switch] $ReadEk
)

$ErrorActionPreference = 'Stop'
# A native command that fails (sc.exe on a service that is not running) must not stop the script
$PSNativeCommandUseErrorActionPreference = $false

$PcpName = 'Microsoft Platform Crypto Provider'
$SoftName = 'Microsoft Software Key Storage Provider'

# The code that PowerShell cannot write: the TBS device query, the parallel signatures and the TLS peers.
# It is C# 5, so that Windows PowerShell 5.1 compiles it.
$source = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace RanzTpmExperiment
{
	public sealed class TbsInfo
	{
		public uint Result;
		public uint TpmVersion;
		public uint InterfaceType;
		public uint ImpRevision;
	}

	// Tbsi_GetDeviceInfo of tbs.dll: which TPM the TPM Base Services see. Result 0 means one answered;
	// 0x8028400F (TBS_E_TPM_NOT_FOUND) means the host has none.
	public static class Tbs
	{
		[StructLayout(LayoutKind.Sequential)]
		private struct TbsDeviceInfo
		{
			public uint StructVersion;
			public uint TpmVersion;
			public uint TpmInterfaceType;
			public uint TpmImpRevision;
		}

		[DllImport("tbs.dll")]
		private static extern uint Tbsi_GetDeviceInfo(uint size, ref TbsDeviceInfo info);

		public static TbsInfo GetDeviceInfo()
		{
			TbsDeviceInfo raw = new TbsDeviceInfo();
			TbsInfo info = new TbsInfo();
			try
			{
				info.Result = Tbsi_GetDeviceInfo((uint)Marshal.SizeOf(typeof(TbsDeviceInfo)), ref raw);
			}
			catch (DllNotFoundException)
			{
				info.Result = 0xFFFFFFFF;
				return info;
			}
			catch (EntryPointNotFoundException)
			{
				info.Result = 0xFFFFFFFE;
				return info;
			}
			info.TpmVersion = raw.TpmVersion;
			info.InterfaceType = raw.TpmInterfaceType;
			info.ImpRevision = raw.TpmImpRevision;
			return info;
		}
	}

	public sealed class SignLoadResult
	{
		public double WallMs;
		public double[] OpMs;
		public int Errors;
		public string FirstError;
	}

	// Several threads, each with a key handle of its own, sign at the same moment: what a TPM that is busy does
	public static class SignLoad
	{
		public static SignLoadResult Run(string provider, string keyName, int threads, int perThread)
		{
			SignLoadResult result = new SignLoadResult();
			List<double> all = new List<double>();
			object guard = new object();
			int errors = 0;
			string firstError = null;
			byte[] digest = new byte[32];
			CountdownEvent ready = new CountdownEvent(threads);
			ManualResetEvent go = new ManualResetEvent(false);
			List<Thread> workers = new List<Thread>();

			for (int t = 0; t < threads; t++)
			{
				Thread worker = new Thread(delegate()
				{
					bool signalled = false;
					try
					{
						using (CngKey key = CngKey.Open(keyName, new CngProvider(provider)))
						using (ECDsaCng ecdsa = new ECDsaCng(key))
						{
							ready.Signal();
							signalled = true;
							go.WaitOne();
							for (int i = 0; i < perThread; i++)
							{
								long t0 = Stopwatch.GetTimestamp();
								try
								{
									ecdsa.SignHash(digest);
								}
								catch (Exception e)
								{
									lock (guard)
									{
										errors++;
										if (firstError == null) firstError = "0x" + e.HResult.ToString("X8") + " " + e.GetType().Name + ": " + e.Message;
									}
									continue;
								}
								double ms = (Stopwatch.GetTimestamp() - t0) * 1000.0 / Stopwatch.Frequency;
								lock (guard) { all.Add(ms); }
							}
						}
					}
					catch (Exception e)
					{
						lock (guard)
						{
							errors++;
							if (firstError == null) firstError = "0x" + e.HResult.ToString("X8") + " " + e.GetType().Name + ": " + e.Message;
						}
						if (!signalled) ready.Signal();
					}
				});
				worker.IsBackground = true;
				worker.Start();
				workers.Add(worker);
			}

			ready.Wait();
			long w0 = Stopwatch.GetTimestamp();
			go.Set();
			foreach (Thread worker in workers) worker.Join();
			result.WallMs = (Stopwatch.GetTimestamp() - w0) * 1000.0 / Stopwatch.Frequency;
			result.OpMs = all.ToArray();
			result.Errors = errors;
			result.FirstError = firstError;
			return result;
		}
	}

	public sealed class TlsResult
	{
		public double[] Ms;
		public string Protocol;
		public string FirstError;
		public int Failures;
		public int ServerSawClientCert;
		public int ServerAccepted;
	}

	// A TLS server and a TLS client over the loopback, both Schannel through SslStream. The server asks for a
	// client certificate when clientCert is given, and accepts only the one with expectedClientThumbprint (a
	// pin, no chain). One handshake ends with one byte of echo, so the time includes the check of the
	// client certificate, which in TLS 1.3 the client learns only from the first read.
	public static class TlsProbe
	{
		public static TlsResult Run(X509Certificate2 serverCert, X509Certificate2 clientCert, string expectedClientThumbprint, int count, int protocols)
		{
			TlsResult res = new TlsResult();
			List<double> times = new List<double>();
			TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
			listener.Start();
			int port = ((IPEndPoint)listener.LocalEndpoint).Port;
			bool requireClient = (clientCert != null);
			string serverThumb = serverCert.Thumbprint;

			Thread server = new Thread(delegate()
			{
				while (true)
				{
					TcpClient accepted;
					try
					{
						accepted = listener.AcceptTcpClient();
					}
					catch (Exception)
					{
						return;
					}
					try
					{
						using (accepted)
						using (SslStream ssl = new SslStream(accepted.GetStream(), false, delegate(object s, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
						{
							if (cert == null) return !requireClient;
							Interlocked.Increment(ref res.ServerSawClientCert);
							return expectedClientThumbprint != null && new X509Certificate2(cert).Thumbprint.Equals(expectedClientThumbprint, StringComparison.OrdinalIgnoreCase);
						}))
						{
							ssl.AuthenticateAsServer(serverCert, requireClient, (SslProtocols)protocols, false);
							int b = ssl.ReadByte();
							if (b >= 0)
							{
								ssl.WriteByte((byte)b);
								ssl.Flush();
								Interlocked.Increment(ref res.ServerAccepted);
							}
						}
					}
					catch (Exception)
					{
					}
				}
			});
			server.IsBackground = true;
			server.Start();

			X509CertificateCollection mine = new X509CertificateCollection();
			if (clientCert != null) mine.Add(clientCert);

			for (int i = 0; i < count; i++)
			{
				long t0 = Stopwatch.GetTimestamp();
				try
				{
					using (TcpClient c = new TcpClient())
					{
						c.Connect(IPAddress.Loopback, port);
						using (SslStream ssl = new SslStream(c.GetStream(), false,
							delegate(object s, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
							{
								return cert != null && new X509Certificate2(cert).Thumbprint.Equals(serverThumb, StringComparison.OrdinalIgnoreCase);
							},
							delegate(object s, string target, X509CertificateCollection local, X509Certificate remote, string[] issuers)
							{
								return clientCert;
							}))
						{
							ssl.AuthenticateAsClient("localhost", mine, (SslProtocols)protocols, false);
							if (res.Protocol == null) res.Protocol = ssl.SslProtocol.ToString() + " (" + ((int)ssl.SslProtocol) + ")";
							ssl.WriteByte(1);
							ssl.Flush();
							if (ssl.ReadByte() < 0) throw new System.IO.IOException("the server closed the stream");
						}
					}
					times.Add((Stopwatch.GetTimestamp() - t0) * 1000.0 / Stopwatch.Frequency);
				}
				catch (Exception e)
				{
					res.Failures++;
					if (res.FirstError == null) res.FirstError = e.GetType().Name + ": " + e.Message;
				}
			}

			listener.Stop();
			res.Ms = times.ToArray();
			return res;
		}
	}
}
'@

if (-not ('RanzTpmExperiment.Tbs' -as [type])) {
	Add-Type -TypeDefinition $source -Language CSharp
}

function Format-HResult([System.Exception] $e) {
	return ('0x{0:X8}' -f $e.HResult)
}

# The error that a call of CNG raised, as one line: its HRESULT, its type and its message
function Get-ErrorText($record) {
	$e = $record.Exception
	while ($e.InnerException -ne $null -and ($e -is [System.Management.Automation.MethodInvocationException] -or $e -is [System.Reflection.TargetInvocationException])) {
		$e = $e.InnerException
	}
	return ('{0} {1}: {2}' -f (Format-HResult $e), $e.GetType().Name, $e.Message.Trim())
}

function Get-Stats([double[]] $values) {
	if ($values -eq $null -or $values.Count -eq 0) { return $null }
	$s = @($values | Sort-Object)
	$n = $s.Count
	if ($n % 2 -eq 1) { $median = $s[[int](($n - 1) / 2)] } else { $median = ($s[$n / 2 - 1] + $s[$n / 2]) / 2 }
	$p95 = $s[[int][Math]::Ceiling(0.95 * $n) - 1]
	$mean = ($s | Measure-Object -Average).Average
	return [pscustomobject][ordered]@{
		Count = $n
		MinMs = [Math]::Round($s[0], 2)
		MedianMs = [Math]::Round($median, 2)
		MeanMs = [Math]::Round($mean, 2)
		P95Ms = [Math]::Round($p95, 2)
		MaxMs = [Math]::Round($s[$n - 1], 2)
	}
}

function Measure-Ms([scriptblock] $action) {
	$t0 = [System.Diagnostics.Stopwatch]::GetTimestamp()
	& $action | Out-Null
	return ([System.Diagnostics.Stopwatch]::GetTimestamp() - $t0) * 1000.0 / [System.Diagnostics.Stopwatch]::Frequency
}

# Every key that the script makes is listed here and deleted in the end, whatever happened
$script:Keys = New-Object System.Collections.ArrayList
$script:Certs = New-Object System.Collections.ArrayList

function New-KeyName() {
	return 'ranz-h4-' + [guid]::NewGuid().ToString('N')
}

# One persisted key of the provider, in the current user's key set (the machine key set with -MachineSet)
# and never exportable. The result holds the key, or the error that the provider gave.
function New-TestKey([string] $Provider, [string] $Algorithm, [int] $Length = 0, [string] $Curve = '', [switch] $MachineSet) {
	$out = [pscustomobject]@{ Key = $null; Name = (New-KeyName); CreateMs = 0.0; Error = '' }
	$params = New-Object System.Security.Cryptography.CngKeyCreationParameters
	$params.Provider = New-Object System.Security.Cryptography.CngProvider -ArgumentList $Provider
	$params.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
	$params.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages
	if ($MachineSet) { $params.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey }
	if ($Length -gt 0) {
		$prop = New-Object System.Security.Cryptography.CngProperty -ArgumentList @('Length', [BitConverter]::GetBytes([int] $Length), [System.Security.Cryptography.CngPropertyOptions]::None)
		$params.Parameters.Add($prop)
	}
	if ($Curve) {
		$bytes = [System.Text.Encoding]::Unicode.GetBytes($Curve + [char] 0)
		$prop = New-Object System.Security.Cryptography.CngProperty -ArgumentList @('ECCCurveName', $bytes, [System.Security.Cryptography.CngPropertyOptions]::None)
		$params.Parameters.Add($prop)
	}
	$alg = [System.Security.Cryptography.CngAlgorithm]::$Algorithm
	try {
		$t0 = [System.Diagnostics.Stopwatch]::GetTimestamp()
		$out.Key = [System.Security.Cryptography.CngKey]::Create($alg, $out.Name, $params)
		$out.CreateMs = [Math]::Round(([System.Diagnostics.Stopwatch]::GetTimestamp() - $t0) * 1000.0 / [System.Diagnostics.Stopwatch]::Frequency, 1)
		[void] $script:Keys.Add([pscustomobject]@{ Name = $out.Name; Provider = $Provider; MachineSet = [bool] $MachineSet })
	} catch {
		$out.Error = Get-ErrorText $_
	}
	return $out
}

function Remove-TestKey([string] $Name, [string] $Provider, [bool] $MachineSet = $false) {
	try {
		$options = [System.Security.Cryptography.CngKeyOpenOptions]::None
		if ($MachineSet) { $options = [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey }
		$k = [System.Security.Cryptography.CngKey]::Open($Name, (New-Object System.Security.Cryptography.CngProvider -ArgumentList $Provider), $options)
		$k.Delete()
		return $true
	} catch {
		return $false
	}
}

function Get-KeyFacts($key) {
	$facts = [ordered]@{
		Algorithm = $key.Algorithm.Algorithm
		Group = $key.AlgorithmGroup.AlgorithmGroup
		Bits = $key.KeySize
		Provider = $key.Provider.Provider
		Exportable = ($key.ExportPolicy -ne [System.Security.Cryptography.CngExportPolicies]::None)
	}
	try {
		# NCRYPT_IMPL_TYPE_PROPERTY: 1 hardware, 2 software, 8 removable, 16 hardware random number generator
		$impl = $key.GetProperty('Impl Type', [System.Security.Cryptography.CngPropertyOptions]::None).GetValue()
		$facts['ImplType'] = ('0x{0:X}' -f [BitConverter]::ToUInt32($impl, 0))
	} catch {
		$facts['ImplType'] = 'unknown: ' + (Get-ErrorText $_)
	}
	return [pscustomobject]$facts
}

# Whether the provider opens at all, as a call that needs no key
function Test-Provider([string] $Name) {
	$r = [ordered]@{ Provider = $Name; Opens = $false; Error = '' }
	try {
		[void] [System.Security.Cryptography.CngKey]::Exists((New-KeyName), (New-Object System.Security.Cryptography.CngProvider -ArgumentList $Name))
		$r.Opens = $true
	} catch {
		$r.Error = Get-ErrorText $_
	}
	return [pscustomobject]$r
}

# A signature or an agreement with the key, and its verification where there is one
function Test-KeyUse($created, [string] $Kind, [string] $Provider) {
	$use = [ordered]@{}
	$key = $created.Key
	$digest = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes('ranz core-h4'))
	if ($Kind -eq 'ecdsa') {
		try {
			$ecdsa = New-Object System.Security.Cryptography.ECDsaCng -ArgumentList $key
			$sig = $null
			$use['SignMs'] = [Math]::Round((Measure-Ms { $script:sig = $ecdsa.SignHash($digest) }), 2)
			$use['VerifyOk'] = $ecdsa.VerifyHash($digest, $script:sig)
			$use['SignatureBytes'] = $script:sig.Length
		} catch {
			$use['Error'] = Get-ErrorText $_
		}
	} elseif ($Kind -eq 'rsa') {
		$rsa = $null
		try {
			$rsa = New-Object System.Security.Cryptography.RSACng -ArgumentList $key
		} catch {
			$use['Error'] = Get-ErrorText $_
		}
		if ($rsa -ne $null) {
			foreach ($pad in @('Pkcs1', 'Pss')) {
				$padding = [System.Security.Cryptography.RSASignaturePadding]::$pad
				try {
					$script:sig = $null
					$use[$pad + 'SignMs'] = [Math]::Round((Measure-Ms { $script:sig = $rsa.SignHash($digest, [System.Security.Cryptography.HashAlgorithmName]::SHA256, $padding) }), 2)
					$use[$pad + 'VerifyOk'] = $rsa.VerifyHash($digest, $script:sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, $padding)
				} catch {
					$use[$pad + 'Error'] = Get-ErrorText $_
				}
			}
		}
	} elseif ($Kind -eq 'ecdh') {
		# The peer is an ephemeral software key on the same curve; its public half is imported into the
		# provider of the key under test, because a secret agreement needs both keys in one provider
		try {
			$peer = New-Object System.Security.Cryptography.ECDiffieHellmanCng -ArgumentList $key.KeySize
			$blob = $peer.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
			$peerPub = $null
			try {
				$peerPub = [System.Security.Cryptography.CngKey]::Import($blob, [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob, (New-Object System.Security.Cryptography.CngProvider -ArgumentList $Provider))
				$use['PeerImport'] = 'into ' + $Provider
			} catch {
				$use['PeerImportError'] = Get-ErrorText $_
				$peerPub = [System.Security.Cryptography.CngKey]::Import($blob, [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
				$use['PeerImport'] = 'into the software provider'
			}
			$ecdh = New-Object System.Security.Cryptography.ECDiffieHellmanCng -ArgumentList $key
			$ecdh.KeyDerivationFunction = [System.Security.Cryptography.ECDiffieHellmanKeyDerivationFunction]::Hash
			$ecdh.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256
			$script:secret = $null
			$use['AgreeMs'] = [Math]::Round((Measure-Ms { $script:secret = $ecdh.DeriveKeyMaterial($peerPub) }), 2)
			$use['SecretBytes'] = $script:secret.Length
		} catch {
			$use['Error'] = Get-ErrorText $_
		}
	}
	return [pscustomobject]$use
}

# The ACL of the file that holds a persisted key, found by the unique name of the key: who may read the
# file is who may use a key whose provider keeps its blob in a file (what the machine key set relies on)
function Get-KeyFileAcl([string] $UniqueName) {
	try {
		$root = Join-Path $env:ProgramData 'Microsoft\Crypto'
		$file = Get-ChildItem -LiteralPath $root -Recurse -Force -Filter $UniqueName -ErrorAction SilentlyContinue | Select-Object -First 1
		if ($file -eq $null) { return 'no file of that name under ProgramData\Microsoft\Crypto' }
		return [pscustomobject]@{ Path = $file.FullName; Folder = $file.Directory.FullName.Substring($env:ProgramData.Length); Sddl = (Get-Acl -LiteralPath $file.FullName).Sddl }
	} catch {
		return Get-ErrorText $_
	}
}

# What a service that runs as a virtual account does with keys. PowerShell cannot be that service (the service
# control manager starts a process and waits for it to answer, and a PowerShell script never does), so the probe
# is a small service of C# that csc.exe of the .NET Framework 4 builds from this text. It reads job.txt next to it
# (line 1: the provider; line 2: the name of a key in the machine key set that an administrator made), tries
# three things, writes result.txt (one name=value line each) and stops itself:
#   OpenMachineKeyAndSign    opens the key of the administrator and signs with it
#   CreateMachineKeyAndSign  makes a key of its own in the machine key set
#   CreateOwnKeyAndSign      makes a key in the key set of its own account, which is where the Node service
#                            keeps its identity key (PeerKeyScope, src/Core/PeerSignal.c)
# For a key that it made it also says where the file of the key is and who may read it.
$probeSource = @'
using System;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace RanzTpmProbe
{
	public sealed class Probe : ServiceBase
	{
		private string dir;
		private CngProvider provider;
		private readonly StringBuilder answer = new StringBuilder();
		private readonly byte[] digest = new byte[32];

		public static void Main()
		{
			ServiceBase.Run(new Probe());
		}

		public Probe()
		{
			ServiceName = "RanzH4Probe";
			CanStop = true;
			// The event log source of a service is made by an administrator; this account is none
			AutoLog = false;
		}

		protected override void OnStart(string[] args)
		{
			dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
			// OnStart must return within the start timeout: the work runs on a thread of its own
			Thread worker = new Thread(Work);
			worker.IsBackground = true;
			worker.Start();
		}

		private static string Describe(Exception e)
		{
			return "0x" + e.HResult.ToString("X8") + " " + e.GetType().Name + ": " + e.Message.Trim();
		}

		private void Say(string name, string value)
		{
			answer.AppendLine(name + "=" + value.Replace("\r", " ").Replace("\n", " "));
		}

		private string SignAndVerify(CngKey key)
		{
			using (ECDsaCng ecdsa = new ECDsaCng(key))
			{
				return "ok, signature verified: " + ecdsa.VerifyHash(digest, ecdsa.SignHash(digest));
			}
		}

		// The file under root (at most depth folders down) that has the name, or null
		private static string FindFile(string root, string name, int depth)
		{
			try
			{
				string[] found = Directory.GetFiles(root, name);
				if (found.Length > 0) return found[0];
				if (depth == 0) return null;
				foreach (string sub in Directory.GetDirectories(root))
				{
					string hit = FindFile(sub, name, depth - 1);
					if (hit != null) return hit;
				}
			}
			catch (Exception)
			{
			}
			return null;
		}

		// Says where the file of a key is and its owner and DACL: who may read the file is who may use the key
		private void SayFile(string label, string uniqueName, bool machine)
		{
			string[] roots;
			if (machine)
			{
				roots = new string[] { Environment.ExpandEnvironmentVariables("%ProgramData%\\Microsoft\\Crypto") };
			}
			else
			{
				roots = new string[] {
					Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
					Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
					Environment.ExpandEnvironmentVariables("%SystemRoot%\\ServiceProfiles\\" + ServiceName)
				};
			}
			string file = null;
			foreach (string root in roots)
			{
				if (root.Length > 0 && file == null) file = FindFile(root, uniqueName, 8);
			}
			Say(label + "File", file == null ? "not found under " + string.Join("; ", roots) : file);
			if (file != null)
			{
				try
				{
					Say(label + "FileSddl", new FileInfo(file).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access));
				}
				catch (Exception e)
				{
					Say(label + "FileSddl", Describe(e));
				}
			}
		}

		// Makes a key of the provider, signs with it, says where its file is, and deletes it
		private string TryCreate(bool machine, string label)
		{
			CngKeyCreationParameters p = new CngKeyCreationParameters();
			p.Provider = provider;
			p.ExportPolicy = CngExportPolicies.None;
			if (machine) p.KeyCreationOptions = CngKeyCreationOptions.MachineKey;
			try
			{
				using (CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, "ranz-h4-svc-" + Guid.NewGuid().ToString("N"), p))
				{
					string result = SignAndVerify(key);
					SayFile(label, key.UniqueName, machine);
					key.Delete();
					return result;
				}
			}
			catch (Exception e)
			{
				return Describe(e);
			}
		}

		private void Work()
		{
			try
			{
				string[] job = File.ReadAllLines(Path.Combine(dir, "job.txt"));
				provider = new CngProvider(job[0].Trim());
				Say("Account", WindowsIdentity.GetCurrent().Name);
				Say("Provider", provider.Provider);
				try
				{
					using (CngKey key = CngKey.Open(job[1].Trim(), provider, CngKeyOpenOptions.MachineKey))
					{
						Say("OpenMachineKeyAndSign", SignAndVerify(key));
					}
				}
				catch (Exception e)
				{
					Say("OpenMachineKeyAndSign", Describe(e));
				}
				Say("CreateMachineKeyAndSign", TryCreate(true, "MachineKey"));
				Say("CreateOwnKeyAndSign", TryCreate(false, "OwnKey"));
			}
			catch (Exception e)
			{
				Say("Failed", Describe(e));
			}
			try
			{
				// Written whole under another name and renamed, so that a reader never sees half of it
				string tmp = Path.Combine(dir, "result.tmp");
				File.WriteAllText(tmp, answer.ToString(), Encoding.UTF8);
				File.Move(tmp, Path.Combine(dir, "result.txt"));
			}
			catch (Exception)
			{
			}
			Thread.Sleep(500);
			try
			{
				Stop();
			}
			catch (Exception)
			{
				Environment.Exit(0);
			}
		}
	}
}
'@

# Builds the probe service from $probeSource in the folder Dir with csc.exe of the .NET Framework 4, which every
# Windows of the script has and which Windows PowerShell 5.1 and PowerShell 7 call the same way. Returns the path
# of probe.exe.
function Build-Probe([string] $Dir) {
	$csc = @("$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe", "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe") |
		Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
	if (-not $csc) { throw 'csc.exe of the .NET Framework 4 was not found' }
	$source = Join-Path $Dir 'probe.cs'
	$exe = Join-Path $Dir 'probe.exe'
	Set-Content -LiteralPath $source -Value $probeSource -Encoding UTF8
	$output = & $csc /nologo /target:exe /optimize+ "/out:$exe" /reference:System.ServiceProcess.dll /reference:System.Core.dll $source | Out-String
	if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe)) { throw ('csc.exe did not build the probe: ' + $output.Trim()) }
	return $exe
}

# One run of the probe: wait until the service is stopped, start it, and wait for its answer, the lines of
# result.txt as properties. For a probe that gave none: what the service control manager says.
function Start-ProbeService([string] $Name, [string] $Dir) {
	$out = Join-Path $Dir 'result.txt'
	for ($i = 0; $i -lt 60 -and (Get-Service -Name $Name).Status -ne 'Stopped'; $i++) { Start-Sleep -Seconds 1 }
	Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
	$began = Get-Date
	$start = ((& sc.exe start $Name | Out-String) -replace '\s+', ' ').Trim()
	for ($i = 0; $i -lt 60 -and -not (Test-Path -LiteralPath $out); $i++) { Start-Sleep -Seconds 1 }
	if (Test-Path -LiteralPath $out) {
		$answer = [ordered]@{}
		foreach ($line in @(Get-Content -LiteralPath $out)) {
			$at = $line.IndexOf('=')
			if ($at -gt 0) { $answer[$line.Substring(0, $at)] = $line.Substring($at + 1) }
		}
		return [pscustomobject]$answer
	}
	$run = [ordered]@{ Error = 'the service wrote no answer in 60 s'; ScStart = $start }
	$run['ScQuery'] = ((& sc.exe query $Name | Out-String) -replace '\s+', ' ').Trim()
	try {
		$run['ScmEvents'] = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $began } -ErrorAction Stop |
			Where-Object { $_.Message -like ('*' + $Name + '*') } | ForEach-Object { '{0} {1}' -f $_.Id, ($_.Message -replace '\s+', ' ') })
	} catch {
		$run['ScmEvents'] = Get-ErrorText $_
	}
	return [pscustomobject]$run
}

# The probe runs twice: with the DACL that the machine key got from its maker, and after the maker gave the
# service read access to the file of the key, as an installer would
function Invoke-AsVirtualAccount([string] $Provider, [string] $MachineKey, $KeyFile) {
	$name = 'RanzH4Probe'
	$dir = Join-Path $env:ProgramData 'RanzH4Probe'
	$result = [ordered]@{ Provider = $Provider }
	$created = $false
	try {
		New-Item -ItemType Directory -Force -Path $dir | Out-Null
		$exe = Build-Probe $dir
		Set-Content -LiteralPath (Join-Path $dir 'job.txt') -Value @($Provider, $MachineKey) -Encoding UTF8
		& sc.exe create $name binPath= $exe obj= "NT SERVICE\$name" start= demand | Out-Null
		if ($LASTEXITCODE -ne 0) { throw ('sc.exe create exited with {0}' -f $LASTEXITCODE) }
		$created = $true
		# As the Node service has it: the service SID is the SID of the virtual account
		& sc.exe sidtype $name unrestricted | Out-Null
		$sid = [regex]::Match((& sc.exe showsid $name | Out-String), 'S-1-5-80-[0-9-]+').Value
		if (-not $sid) { throw 'sc.exe showsid gave no service SID' }
		& icacls.exe $dir /grant ('*{0}:(OI)(CI)M' -f $sid) | Out-Null
		$result['ServiceSid'] = $sid
		$result['DefaultAcl'] = Start-ProbeService $name $dir
		if ($KeyFile -ne $null -and $KeyFile.PSObject.Properties['Path'] -ne $null) {
			& icacls.exe $KeyFile.Path /grant ('*{0}:R' -f $sid) | Out-Null
			$result['AfterGrantOnKeyFile'] = Start-ProbeService $name $dir
		} else {
			$result['AfterGrantOnKeyFile'] = 'not run: the file of the key was not found'
		}
	} catch {
		$result['Error'] = Get-ErrorText $_
	} finally {
		if ($created) {
			& sc.exe stop $name | Out-Null
			& sc.exe delete $name | Out-Null
		}
		# The process of the service may take a moment to let go of probe.exe
		for ($i = 0; $i -lt 10; $i++) {
			Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
			if (-not (Test-Path -LiteralPath $dir)) { break }
			Start-Sleep -Seconds 1
		}
	}
	return [pscustomobject]$result
}

$results = [ordered]@{ Started = (Get-Date).ToUniversalTime().ToString('o'); PowerShell = $PSVersionTable.PSVersion.ToString() }

try {
	# ---- E1: the host
	$tbs = [RanzTpmExperiment.Tbs]::GetDeviceInfo()
	$os = Get-CimInstance Win32_OperatingSystem
	$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	$results['E1_Host'] = [pscustomobject][ordered]@{
		OS = $os.Caption
		Build = $os.BuildNumber
		Architecture = $env:PROCESSOR_ARCHITECTURE
		Elevated = $admin
		TbsResult = ('0x{0:X8}' -f $tbs.Result)
		TpmFound = ($tbs.Result -eq 0)
		TpmVersion = $tbs.TpmVersion
		TpmInterfaceType = $tbs.InterfaceType
		TpmImplementationRevision = $tbs.ImpRevision
	}
	if ($admin) {
		try {
			$tpm = Get-Tpm
			$results['E1_Host'] | Add-Member -NotePropertyName GetTpm -NotePropertyValue ([pscustomobject]@{
				TpmPresent = $tpm.TpmPresent; TpmReady = $tpm.TpmReady; ManufacturerIdTxt = $tpm.ManufacturerIdTxt; ManufacturerVersion = $tpm.ManufacturerVersion
				LockedOut = $tpm.LockedOut; LockoutCount = $tpm.LockoutCount; LockoutMax = $tpm.LockoutMax; LockoutHealTimeSeconds = $tpm.LockoutHealTime
			})
		} catch {
			$results['E1_Host'] | Add-Member -NotePropertyName GetTpm -NotePropertyValue (Get-ErrorText $_)
		}
	}

	# ---- E2: the providers
	$useTpm = (-not $NoTpm)
	$providers = @($SoftName)
	if ($useTpm) { $providers += $PcpName }
	$e2 = @()
	foreach ($p in $providers) { $e2 += Test-Provider $p }
	$results['E2_Providers'] = $e2
	$open = @{}
	foreach ($p in $e2) { $open[$p.Provider] = $p.Opens }

	# ---- E3: which kinds of key each provider makes
	$matrix = @(
		@{ Label = 'ECDSA P-256'; Alg = 'ECDsaP256'; Use = 'ecdsa' }
		@{ Label = 'ECDSA P-384'; Alg = 'ECDsaP384'; Use = 'ecdsa' }
		@{ Label = 'ECDSA P-521'; Alg = 'ECDsaP521'; Use = 'ecdsa' }
		@{ Label = 'ECDH P-256'; Alg = 'ECDiffieHellmanP256'; Use = 'ecdh' }
		@{ Label = 'ECDH P-384'; Alg = 'ECDiffieHellmanP384'; Use = 'ecdh' }
		@{ Label = 'ECDH P-521'; Alg = 'ECDiffieHellmanP521'; Use = 'ecdh' }
		@{ Label = 'ECDH curve25519 (X25519)'; Alg = 'ECDiffieHellman'; Curve = 'curve25519'; Use = 'none' }
	)
	if ($IncludeRsa) {
		$matrix += @{ Label = 'RSA 2048'; Alg = 'Rsa'; Length = 2048; Use = 'rsa' }
		$matrix += @{ Label = 'RSA 3072'; Alg = 'Rsa'; Length = 3072; Use = 'rsa' }
		$matrix += @{ Label = 'RSA 4096'; Alg = 'Rsa'; Length = 4096; Use = 'rsa' }
	}
	$e3 = @()
	foreach ($p in $providers) {
		foreach ($m in $matrix) {
			$row = [ordered]@{ Provider = $p; Kind = $m.Label; Created = $false; CreateMs = $null; Error = '' }
			if (-not $open[$p]) {
				$row.Error = 'the provider does not open (E2)'
				$e3 += [pscustomobject]$row
				continue
			}
			$length = 0; if ($m.ContainsKey('Length')) { $length = $m.Length }
			$curve = ''; if ($m.ContainsKey('Curve')) { $curve = $m.Curve }
			$created = New-TestKey -Provider $p -Algorithm $m.Alg -Length $length -Curve $curve
			if ($created.Key -eq $null) {
				$row.Error = $created.Error
			} else {
				$row.Created = $true
				$row.CreateMs = $created.CreateMs
				$row['Facts'] = Get-KeyFacts $created.Key
				if ($m.Use -ne 'none') { $row['Use'] = Test-KeyUse $created $m.Use $p }
				$created.Key.Dispose()
			}
			$e3 += [pscustomobject]$row
		}
	}
	$results['E3_Kinds'] = $e3

	# ---- E4: the time of one signature, one agreement, and of several at once
	$e4 = @()
	foreach ($p in $providers) {
		$row = [ordered]@{ Provider = $p }
		if (-not $open[$p]) {
			$row['Error'] = 'the provider does not open (E2)'
			$e4 += [pscustomobject]$row
			continue
		}
		$created = New-TestKey -Provider $p -Algorithm 'ECDsaP256'
		if ($created.Key -eq $null) {
			$row['Error'] = $created.Error
			$e4 += [pscustomobject]$row
			continue
		}
		$digest = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes('ranz core-h4 timing'))
		$ecdsa = New-Object System.Security.Cryptography.ECDsaCng -ArgumentList $created.Key
		try {
			$first = Measure-Ms { [void] $ecdsa.SignHash($digest) }
			$row['FirstSignMs'] = [Math]::Round($first, 2)
			for ($i = 0; $i -lt 3; $i++) { [void] $ecdsa.SignHash($digest) }
			$times = New-Object 'System.Collections.Generic.List[double]'
			for ($i = 0; $i -lt $SignCount; $i++) { $times.Add((Measure-Ms { [void] $ecdsa.SignHash($digest) })) }
			$row['SequentialSign'] = Get-Stats $times.ToArray()
			$created.Key.Dispose()
			$load = [RanzTpmExperiment.SignLoad]::Run($p, $created.Name, $Threads, [Math]::Max(1, [int]($SignCount / $Threads)))
			$row['ParallelSign'] = [pscustomobject][ordered]@{
				Threads = $Threads
				WallMs = [Math]::Round($load.WallMs, 1)
				Operations = $load.OpMs.Count
				Errors = $load.Errors
				FirstError = $load.FirstError
				PerOperation = Get-Stats $load.OpMs
			}
			if ($load.OpMs.Count -gt 0) {
				$row['ParallelSign'] | Add-Member -NotePropertyName OperationsPerSecond -NotePropertyValue ([Math]::Round($load.OpMs.Count / ($load.WallMs / 1000.0), 1))
			}
		} catch {
			$row['Error'] = Get-ErrorText $_
		}
		[void] (Remove-TestKey $created.Name $p)
		$e4 += [pscustomobject]$row
	}
	$results['E4_Timing'] = $e4

	# ---- E5: a TLS handshake with a client certificate whose key is in the provider
	if (-not $SkipTls) {
		$tlsProtocol = 3072       # SslProtocols.Tls12
		if ($PSVersionTable.PSVersion.Major -ge 7) { $tlsProtocol = 12288 }   # SslProtocols.Tls13
		$e5 = [ordered]@{ RequestedProtocol = $tlsProtocol; Runs = @() }

		function New-TestCert([string] $Provider, [string] $Subject) {
			$out = [pscustomobject]@{ Cert = $null; Error = '' }
			try {
				$made = New-SelfSignedCertificate -Subject $Subject -KeyAlgorithm ECDSA_nistP256 -Provider $Provider -KeyExportPolicy NonExportable `
					-KeyUsage DigitalSignature -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2') `
					-HashAlgorithm SHA256 -NotAfter (Get-Date).AddHours(2) -CertStoreLocation 'Cert:\CurrentUser\My'
				# Read it again from the store: in PowerShell 7 the cmdlet runs in Windows PowerShell and hands back a copy
				$out.Cert = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $made.Thumbprint)
				[void] $script:Certs.Add($out.Cert)
			} catch {
				$out.Error = Get-ErrorText $_
			}
			return $out
		}

		$server = New-TestCert $SoftName 'CN=localhost'
		$clientSoft = New-TestCert $SoftName 'CN=ranz-h4-client-software'
		$clientTpm = $null
		if ($useTpm -and $open[$PcpName]) { $clientTpm = New-TestCert $PcpName 'CN=ranz-h4-client-tpm' }
		if ($server.Cert -eq $null) {
			$e5['Error'] = 'the server certificate was not made: ' + $server.Error
		} else {
			$plans = @(
				@{ Name = 'no client certificate'; Client = $null; Pin = $null; Count = $HandshakeCount }
				@{ Name = 'client certificate, key in the software provider'; Client = $clientSoft; Pin = 'self'; Count = $HandshakeCount }
			)
			if ($clientTpm -ne $null) {
				$plans += @{ Name = 'client certificate, key in the TPM'; Client = $clientTpm; Pin = 'self'; Count = $HandshakeCount }
			} elseif ($useTpm) {
				$e5['TpmCertificate'] = 'not made: ' + $(if ($open[$PcpName]) { 'the TPM provider refused it' } else { 'the TPM provider does not open (E2)' })
			}
			# The pin check: the server pins another key than the one that the client presents
			$plans += @{ Name = 'client certificate that the server does not pin (must be refused)'; Client = $clientSoft; Pin = 'other'; Count = 1 }
			foreach ($plan in $plans) {
				$entry = [ordered]@{ Run = $plan.Name }
				if ($plan.Client -ne $null -and $plan.Client.Cert -eq $null) {
					$entry['Error'] = 'the client certificate was not made: ' + $plan.Client.Error
					$e5.Runs += [pscustomobject]$entry
					continue
				}
				$clientCert = $null; $pin = $null
				if ($plan.Client -ne $null) {
					$clientCert = $plan.Client.Cert
					$pin = $clientCert.Thumbprint
					if ($plan.Pin -eq 'other') { $pin = ('0' * 40) }
				}
				try {
					$r = [RanzTpmExperiment.TlsProbe]::Run($server.Cert, $clientCert, $pin, $plan.Count, $tlsProtocol)
					$entry['Protocol'] = $r.Protocol
					$entry['Handshakes'] = $plan.Count
					$entry['Failures'] = $r.Failures
					$entry['FirstError'] = $r.FirstError
					$entry['ServerSawClientCertificate'] = $r.ServerSawClientCert
					$entry['ServerAccepted'] = $r.ServerAccepted
					if ($r.Ms.Count -gt 0) {
						$entry['FirstMs'] = [Math]::Round($r.Ms[0], 2)
						$entry['Handshake'] = Get-Stats $r.Ms
					}
				} catch {
					$entry['Error'] = Get-ErrorText $_
				}
				$e5.Runs += [pscustomobject]$entry
			}
		}
		$results['E5_Tls'] = [pscustomobject]$e5
	}

	# ---- E6: the machine key set, and a service that runs as a virtual account
	if ($Machine) {
		if (-not $admin) {
			$results['E6_Machine'] = 'not run: it needs an elevated process'
		} else {
			$e6 = @()
			foreach ($p in $providers) {
				$row = [ordered]@{ Provider = $p }
				if (-not $open[$p]) {
					$row['Error'] = 'the provider does not open (E2)'
					$e6 += [pscustomobject]$row
					continue
				}
				$made = New-TestKey -Provider $p -Algorithm 'ECDsaP256' -MachineSet
				if ($made.Key -eq $null) {
					$row['AdminMakesMachineKey'] = $made.Error
					$e6 += [pscustomobject]$row
					continue
				}
				$row['AdminMakesMachineKey'] = ('ok in {0} ms' -f $made.CreateMs)
				$row['Key'] = Get-KeyFacts $made.Key
				$row['AdminSigns'] = Test-KeyUse $made 'ecdsa' $p
				$keyFile = Get-KeyFileAcl $made.Key.UniqueName
				$row['KeyFile'] = $keyFile
				$made.Key.Dispose()
				$row['VirtualAccount'] = Invoke-AsVirtualAccount $p $made.Name $keyFile
				$e6 += [pscustomobject]$row
			}
			$results['E6_Machine'] = $e6
		}
	}

	# ---- E7: the endorsement key and the certificates of the manufacturer
	if ($ReadEk) {
		if (-not $admin) {
			$results['E7_Ek'] = 'not run: it needs an elevated process'
		} elseif (-not $useTpm) {
			$results['E7_Ek'] = 'not run: -NoTpm'
		} else {
			$e7 = [ordered]@{}
			try {
				$ek = Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256
				$e7['IsPresent'] = $ek.IsPresent
				$e7['PublicKeyHash'] = $ek.PublicKeyHash
				$manufacturer = @($ek.ManufacturerCertificates | Where-Object { $_ -ne $null })
				$additional = @($ek.AdditionalCertificates | Where-Object { $_ -ne $null })
				$e7['ManufacturerCertificates'] = $manufacturer.Count
				$e7['AdditionalCertificates'] = $additional.Count
				$e7['Certificates'] = @(($manufacturer + $additional) | ForEach-Object {
					[pscustomobject]@{ Subject = $_.Subject; Issuer = $_.Issuer; NotAfter = $_.NotAfter.ToString('o') }
				})
				if ($manufacturer.Count -gt 0) {
					$x509 = 'System.Security.Cryptography.X509Certificates.X509Certificate2'
					$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
					$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
					$chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(10)
					foreach ($extra in $additional) { [void] $chain.ChainPolicy.ExtraStore.Add((New-Object $x509 -ArgumentList (, $extra.RawData))) }
					$leaf = New-Object $x509 -ArgumentList (, $manufacturer[0].RawData)
					$e7['ChainBuilds'] = $chain.Build($leaf)
					$e7['ChainStatus'] = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() })
					$e7['ChainSubjects'] = @($chain.ChainElements | ForEach-Object { $_.Certificate.Subject })
				}
			} catch {
				$e7['Error'] = Get-ErrorText $_
			}
			$results['E7_Ek'] = [pscustomobject]$e7
		}
	}
} catch {
	$results['Fatal'] = Get-ErrorText $_
} finally {
	foreach ($c in $script:Certs) {
		try {
			$ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)
			if ($ecdsa -ne $null -and $ecdsa.Key -ne $null) { $ecdsa.Key.Delete() }
		} catch { }
		try { Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $c.Thumbprint) -Force } catch { }
	}
	foreach ($k in $script:Keys) { [void] (Remove-TestKey $k.Name $k.Provider $k.MachineSet) }
}

$results['Finished'] = (Get-Date).ToUniversalTime().ToString('o')
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$json = $results | ConvertTo-Json -Depth 10
Set-Content -LiteralPath (Join-Path $OutDir 'results.json') -Value $json -Encoding UTF8

# The report: the numbers that the ADR quotes, one table for each experiment
function Join-Properties($object) {
	if ($object -eq $null) { return '' }
	return (($object.PSObject.Properties | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; ')
}

$text = New-Object System.Text.StringBuilder
[void] $text.AppendLine('E1 the host')
[void] $text.AppendLine((($results['E1_Host'] | Format-List | Out-String).TrimEnd()))
if ($results.Contains('E2_Providers')) {
	[void] $text.AppendLine([Environment]::NewLine + 'E2 the providers')
	[void] $text.AppendLine((($results['E2_Providers'] | Format-Table -AutoSize -Wrap | Out-String -Width 200).TrimEnd()))
}
if ($results.Contains('E3_Kinds')) {
	[void] $text.AppendLine([Environment]::NewLine + 'E3 the kinds of key that each provider makes')
	$rows = $results['E3_Kinds'] | ForEach-Object {
		[pscustomobject]@{ Provider = $_.Provider; Kind = $_.Kind; Created = $_.Created; CreateMs = $_.CreateMs; Use = (Join-Properties $_.Use); Error = $_.Error }
	}
	[void] $text.AppendLine((($rows | Format-Table -AutoSize -Wrap | Out-String -Width 240).TrimEnd()))
}
if ($results.Contains('E4_Timing')) {
	[void] $text.AppendLine([Environment]::NewLine + 'E4 the time of an ECDSA P-256 signature, in ms')
	$rows = $results['E4_Timing'] | ForEach-Object {
		[pscustomobject]@{ Provider = $_.Provider; First = $_.FirstSignMs; Sequential = (Join-Properties $_.SequentialSign); Parallel = (Join-Properties $_.ParallelSign); Error = $_.Error }
	}
	[void] $text.AppendLine((($rows | Format-List | Out-String -Width 240).TrimEnd()))
}
if ($results.Contains('E5_Tls')) {
	[void] $text.AppendLine([Environment]::NewLine + 'E5 TLS handshakes over the loopback, in ms')
	[void] $text.AppendLine((($results['E5_Tls'].Runs | ForEach-Object {
		[pscustomobject]@{ Run = $_.Run; Protocol = $_.Protocol; Failures = $_.Failures; Saw = $_.ServerSawClientCertificate; First = $_.FirstMs; Handshake = (Join-Properties $_.Handshake); Error = $_.Error; FirstError = $_.FirstError }
	} | Format-List | Out-String -Width 240).TrimEnd()))
}
foreach ($section in @(@('E6_Machine', 'E6 the machine key set and a service that runs as a virtual account'), @('E7_Ek', 'E7 the endorsement key and the certificates of the manufacturer'))) {
	if ($results.Contains($section[0])) {
		[void] $text.AppendLine([Environment]::NewLine + $section[1])
		[void] $text.AppendLine((($results[$section[0]] | ConvertTo-Json -Depth 8).TrimEnd()))
	}
}
if ($results.Contains('Fatal')) { [void] $text.AppendLine([Environment]::NewLine + 'The script stopped on: ' + $results['Fatal']) }
$report = $text.ToString()
Set-Content -LiteralPath (Join-Path $OutDir 'report.txt') -Value $report -Encoding UTF8
Write-Host $report
