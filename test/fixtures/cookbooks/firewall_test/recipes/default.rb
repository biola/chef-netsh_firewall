#
# Cookbook Name:: firewall_test
# Recipe:: default
#

# Disable unmanaged rules
include_recipe 'netsh_firewall::default'

# Firewall rule definitions
netsh_firewall_rule 'Windows Remote Management (HTTPS-In)' do
  description 'Test firewall rule #1'
  localport '5986'
end

netsh_firewall_rule 'Splunk (TCP-Out)' do
  description 'Test firewall rule #2'
  direction :out
  profile :domain
  remoteip '192.168.1.11'
  remoteport '9997'
end

netsh_firewall_rule 'Ping (ICMP-In)' do
  description 'Test firewall rule #3'
  direction :in
  profile :domain
  protocol :icmpv4
end

netsh_firewall_rule 'Web server' do
  description 'Test firewall rule #4'
  localport %w[80 443]
  remoteip %w[192.168.1.0/24 192.168.2.10 172.16.0.0/16]
end

netsh_firewall_profile 'all' do
  inbound :block
  outbound :allow
end
