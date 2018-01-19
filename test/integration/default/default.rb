# The Inspec reference, with examples and extensive documentation, can be
# found at https://docs.chef.io/inspec_reference.html

describe command('netsh advfirewall firewall show rule all') do
  its('stdout') { should match /Windows Remote Management \(HTTPS\-In\)[\s\w\-\:\,]*LocalPort\:\s*5986/m }
  its('stdout') { should match /Splunk \(TCP\-Out\)[\s\w\-\:\,]*RemoteIP\:\s*192\.168\.1\.11\/32/m }
  its('stdout') { should match /Ping \(ICMP\-In\)[\s\w\-\:\,]*Protocol\:\s*ICMPv4/m }
  its('stdout') { should match /Web server[\s\w\-\:\,]*RemoteIP\:\s*172\.16\.0\.0\/16,192\.168\.1\.0\/24,192\.168\.2\.10\/32[\s\w\:]*LocalPort\:\s*443,80/m }
  its('stdout') { should match /Remote Desktop[\s-]*Enabled\:\s*No/m }
end

describe command('netsh advfirewall show all') do
  its('stdout') { should match /Domain Profile Settings\:[\s-]*State\s*ON\s*Firewall Policy\s*BlockInbound,AllowOutbound/m }
end
