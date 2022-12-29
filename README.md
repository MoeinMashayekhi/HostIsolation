# HostIsolator

Isolate, and desolate host using the Windows Firewall.

You can run this script with MEDC, Domain Group Policy, PSRemoting , etc., on your target host, then it will restrict all the inbound and outbound connections to only allowed hosts.

## How to run

1. Replace value of $allowedHosts variable with your proper hosts (for example specify IP of your SIEM and FQDN of your EDR).
2. Run the script with proper parameter.

### For isolation
  ```powershell
  HostIsolator.ps1 isolate
  ```
### For desolation
  ```powershell
  HostIsolator.ps1 desolate
  ```

