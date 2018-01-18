#
# Cookbook Name:: netsh_firewall
# Provider:: rule
#
# Copyright 2018 Biola University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Firewall rule creation actions
action :allow do
  new_resource.updated_by_last_action(true) if manage_rule
end

action :block do
  new_resource.updated_by_last_action(true) if manage_rule
end

# Disable a system firewall rule
action :disable do
  rule = parse_rule_output
  if rule['enabled'] == 'yes'
    execute "netsh advfirewall firewall set rule name=\"#{new_resource.name}\" new enable=no"
    new_resource.updated_by_last_action(true)
  end
end

# Enable a system firewall rule
action :enable do
  rule = parse_rule_output
  if rule['enabled'] == 'no'
    execute "netsh advfirewall firewall set rule name=\"#{new_resource.name}\" new enable=yes"
    new_resource.updated_by_last_action(true)
  end
end

# Add a new firewall rule
def add_rule
  cmd = 'netsh advfirewall firewall add rule '
  rule_args.each do |k, v|
    cmd += "#{k}=#{v} "
  end
  execute cmd
  true
end

# Convert IP addresses to CIDR notation to match netsh output
def cidr(ip_list)
  return ip_list if ip_list == 'any'
  ips = []
  ip_list.split(',').each do |ip|
    ips << (ip.include?('/') ? ip.strip : ip.strip + '/32')
  end
  ips.join(',')
end

# Map netsh output to resource property names
def cmd_map(k)
  {
    'direction' => 'dir',
    'profiles' => 'profile',
    'rule name' => 'name'
  }[k] || k
end

# Create or replace a rule if needed
# Return false if the resource is up to date
def manage_rule
  if rule_exists?
    if rule_needs_update? && !system_rule?
      execute "netsh advfirewall firewall delete rule name=\"#{new_resource.name}\""
      add_rule
    else
      false
    end
  else
    add_rule
  end
end

# Parse netsh output for a rule
# Return a hash with keys and values in lowercase
def parse_rule_output
  raise "Firewall rule '#{new_resource.name}' not found." unless rule_exists?
  rule = {}
  cmd = Mixlib::ShellOut.new("netsh advfirewall firewall show rule name=\"#{new_resource.name}\" verbose")
  cmd.run_command
  cmd.stdout.lines("\r\n") do |line|
    next if line.empty? || line =~ /^Ok/ || line =~ /^-/
    k, v = line.split(': ')
    v = 'any' if k == 'Profiles' && v.strip == 'Domain,Private,Public'
    k = 'name' if k.casecmp('Rule Name')
    rule[cmd_map(k.downcase.chomp)] = v.strip.downcase unless v.nil?
  end
  rule
end

# Create a hash of resource properties
# Format the parameters for netsh
def rule_args
  args = {}
  args['name'] = "\"#{new_resource.name}\""
  args['description'] = "\"#{new_resource.description}\"" if new_resource.description
  args['dir'] = new_resource.dir.to_s
  args['localip'] = cidr(new_resource.localip)
  args['localport'] = new_resource.localport unless new_resource.protocol.to_s.include? 'icmp'
  args['remoteip'] = cidr(new_resource.remoteip)
  args['remoteport'] = new_resource.remoteport unless new_resource.protocol.to_s.include? 'icmp'
  args['protocol'] = new_resource.protocol.to_s
  args['profile'] = new_resource.profile.to_s
  args['program'] = "\"#{new_resource.program}\"" if new_resource.program
  # There can only be one action
  if new_resource.action.is_a? Array
    args['action'] = new_resource.action.first.to_s
  elsif new_resource.action.is_a? Symbol
    args['action'] = new_resource.action.to_s
  end
  args
end

# Determine if a rule exists
def rule_exists?
  cmd = Mixlib::ShellOut.new("netsh advfirewall firewall show rule name=\"#{new_resource.name}\"")
  cmd.run_command
  !cmd.stdout.include? 'No rules match the specified criteria'
end

# Determine if a rule needs to be updated
# Compare the existing rule parameters with the new resource parameters
def rule_needs_update?
  new_rule = rule_args
  existing_rule = parse_rule_output
  Chef::Log.debug("Parsed output: #{existing_rule}")
  diff = []
  new_rule.each do |k, v|
    diff << k unless existing_rule.key? k
    diff << k if v.downcase.delete('"') != existing_rule[k]
  end
  diff << 'enabled' unless existing_rule['enabled'] == 'yes'
  Chef::Log.debug("Updated parameters: #{diff}") unless diff.empty?
  !diff.empty?
end

# Determine if an existing rule is manageable
# Don't attempt to modify built-in rules or rules set by group policy
def system_rule?
  existing_rule = parse_rule_output
  if !existing_rule['grouping'].empty?
    Chef::Log.error("Firewall rule '#{new_resource.name}' is part of a system group.")
    true
  elsif existing_rule['rule source'] != 'local setting'
    Chef::Log.error("Firewall rule '#{new_resource.name}' is set by group policy.")
    true
  end
  false
end
