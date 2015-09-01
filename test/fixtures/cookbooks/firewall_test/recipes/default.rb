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
  dir :out
  profile :domain
  remoteip '192.168.1.11'
  remoteport '9997'
end

netsh_firewall_profile 'all' do
  inbound :block
  outbound :allow
end
