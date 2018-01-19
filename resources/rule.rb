#
# Cookbook Name:: netsh_firewall
# Resource:: rule
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

property :name, String, name_property: true
property :description, String, default: 'Managed with Chef'
property :direction, equal_to: [:in, :out], default: :in
property :enabled, equal_to: %w[yes no], default: 'yes'
property :localip, [Array, String], coerce: proc { |v| coerce_ip(v) }, default: 'any'
property :localport, [Array, String], coerce: proc { |v| coerce_port(v) }, default: 'any'
property :profiles, [Array, String, Symbol], coerce: proc { |v| coerce_profiles(v) }, default: [:domain, :private, :public], desired_state: false
property :program, [String, nil]
property :protocol, equal_to: [:any, :icmpv4, :icmpv6, :tcp, :udp], default: :tcp
property :remoteip, [Array, String], coerce: proc { |v| coerce_ip(v) }, default: 'any'
property :remoteport, [Array, String], coerce: proc { |v| coerce_port(v) }, default: 'any'

alias dir direction
alias profile profiles

load_current_value do
  if rule_exists?
    rule = parse_rule_output
    description rule['Description'] if rule['Description']
    direction rule['Direction'].downcase.to_sym if rule['Direction']
    enabled rule['Enabled'].downcase
    localip coerce_ip(rule['LocalIP']) if rule['LocalIP']
    localport coerce_port(rule['LocalPort']) if rule['LocalPort']
    profiles coerce_profiles(rule['Profiles']) if rule['Profiles']
    program rule['Program'] if rule['Program']
    protocol rule['Protocol'].downcase.to_sym if rule['Protocol']
    remoteip coerce_ip(rule['RemoteIP']) if rule['RemoteIP']
    remoteport coerce_port(rule['RemotePort']) if rule['RemotePort']
  else
    current_value_does_not_exist!
  end
end

action :allow do
  converge_if_changed do
    manage_rule
    new_resource.updated_by_last_action(true)
  end
end

action :block do
  converge_if_changed do
    manage_rule
    new_resource.updated_by_last_action(true)
  end
end

# Disable a system firewall rule
action :disable do
  if parse_rule_output['Enabled'] == 'Yes'
    cmd = "netsh advfirewall firewall set rule name=\"#{new_resource.name}\" "\
      "profile=\"#{formatted_profiles}\" new enable=no"
    shell_out!(cmd)
    new_resource.updated_by_last_action(true)
  end
end

# Enable a system firewall rule
action :enable do
  if parse_rule_output['Enabled'] == 'No'
    cmd = "netsh advfirewall firewall set rule name=\"#{new_resource.name}\" "\
      "profile=\"#{formatted_profiles}\" new enable=yes"
    shell_out!(cmd)
    new_resource.updated_by_last_action(true)
  end
end

# Allowed firewall rule profiles
def allowed_profiles
  [:any, :domain, :private, :public]
end

# Convert IPs/subnets to a sorted array of CIDRs
def coerce_ip(ips)
  return ['any'] if ips.is_a?(String) && ips.downcase == 'any'
  list = ips.dup if ips.is_a?(Array)
  list = ips.delete(' ').split(',') if ips.is_a?(String)
  list.map! { |ip| ip.include?('/') ? ip : ip + '/32' }
  list.uniq.sort
end

# Convert ports to a sorted array
def coerce_port(ports)
  return ['any'] if ports.is_a?(String) && ports.downcase == 'any'
  list = ports.dup if ports.is_a?(Array)
  list = ports.delete(' ').split(',') if ports.is_a?(String)
  list.uniq.sort
end

# Convert profiles to an array of validated values
def coerce_profiles(profiles)
  list = profiles.dup if profiles.is_a?(Array)
  list = profiles.split(',') if profiles.is_a?(String)
  list = [profiles] if profiles.is_a?(Symbol)
  list.map! { |p| p.downcase.to_sym }
  list = [:domain, :private, :public] if list == [:any]
  return list if list.reject { |p| allowed_profiles.include? p }.empty?
  Chef::Log.error('The specified firewall rule profiles are not recognized')
end

# Format the firewall rule arguments as a string
def formatted_args
  argstring = ''
  rule_args.each do |k, v|
    argstring += "#{k}=#{v} "
  end
  argstring
end

# Format the firewall profiles as a string
def formatted_profiles
  profiles.map { |p| p.to_s.capitalize }.join(',')
end

# Create or replace a rule if needed
def manage_rule
  if rule_exists?
    unless system_rule?
      shell_out!("netsh advfirewall firewall delete rule name=\"#{name}\"")
      shell_out!("netsh advfirewall firewall add rule #{formatted_args}")
    end
  else
    shell_out!("netsh advfirewall firewall add rule #{formatted_args}")
  end
end

# Parse netsh output for a rule and return a hash
def parse_rule_output
  raise "Firewall rule '#{name}' not found." unless rule_exists?
  rule = {}
  cmd = shell_out!("netsh advfirewall firewall show rule name=\"#{name}\" profile=\"#{formatted_profiles}\" verbose")
  cmd.stdout.lines("\r\n") do |line|
    next if line.nil? || line.empty? || line =~ /^Ok/ || line =~ /^-/
    k, v = line.split(': ')
    v = 'any' if k == 'Profiles' && v.strip == 'Domain,Private,Public'
    rule[k.chomp] = v.strip unless v.nil?
  end
  rule
end

# Create a hash of resource properties
# Format the parameters for netsh
def rule_args
  args = {}
  args['name'] = "\"#{name}\""
  args['description'] = "\"#{description}\"" if description
  args['dir'] = direction.to_s
  args['enable'] = enabled
  args['localip'] = localip.join(',')
  args['localport'] = localport.join(',') unless protocol.to_s.include? 'icmp'
  args['remoteip'] = remoteip.join(',')
  args['remoteport'] = remoteport.join(',') unless protocol.to_s.include? 'icmp'
  args['protocol'] = protocol.to_s
  args['profile'] = profiles.join(',')
  args['program'] = "\"#{program}\"" if program
  if action.is_a?(Array)
    args['action'] = action.include?(:allow) ? 'allow' : 'block'
  elsif action.is_a?(Symbol)
    args['action'] = action.to_s
  end
  args
end

# Determine if a rule exists
def rule_exists?
  cmd = shell_out("netsh advfirewall firewall show rule name=\"#{name}\" profile=\"#{formatted_profiles}\"")
  !cmd.stdout.include? 'No rules match the specified criteria'
end

# Determine if an existing rule is manageable
# Don't attempt to modify built-in rules or rules set by group policy
def system_rule?
  existing_rule = parse_rule_output
  if !existing_rule['Grouping'].nil? && !existing_rule['Grouping'].empty?
    Chef::Log.warn("Firewall rule '#{name}' is part of a system group.")
    true
  elsif existing_rule['Rule source'] != 'Local Setting'
    Chef::Log.warn("Firewall rule '#{name}' is set by group policy.")
    true
  end
  false
end
