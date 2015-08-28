#
# Cookbook Name:: netsh_firewall
# Provider:: profile
#
# Copyright 2015 Biola University
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

# Disable a firewall profile
action :disable do
  state = execute "netsh advfirewall set #{profile_name} state off" do
    only_if { profile_enabled? }
  end
  new_resource.updated_by_last_action(true) if state.updated_by_last_action?
end

# Enable a firewall profile and ensure the policy is up to date
action :enable do
  state = execute "netsh advfirewall set #{profile_name} state on" do
    not_if { profile_enabled? }
  end
  policy = execute "netsh advfirewall set #{profile_name} firewallpolicy #{firewall_policy}" do
    only_if { policy_needs_update? }
  end
  new_resource.updated_by_last_action(true) if state.updated_by_last_action? ||
                                               policy.updated_by_last_action?
end

def firewall_policy
  "#{new_resource.inbound}inbound,#{new_resource.outbound}outbound"
end

def policy_needs_update?
  if new_resource.name == 'all'
    profile_state('domainprofile')['firewall policy'] != firewall_policy ||
      profile_state('privateprofile')['firewall policy'] != firewall_policy ||
      profile_state('publicprofile')['firewall policy'] != firewall_policy
  else
    profile_state(profile_name)['firewall policy'] != firewall_policy
  end
end

def profile_name
  return 'allprofiles' if new_resource.name == 'all'
  "#{new_resource.name}profile"
end

def profile_enabled?
  if new_resource.name == 'all'
    profile_state('domainprofile')['state'] == 'on' &&
      profile_state('privateprofile')['state'] == 'on' &&
      profile_state('publicprofile')['state'] == 'on'
  else
    profile_state(profile_name)['state'] == 'on'
  end
end

# Retrieve the state of the given profile and parse the output
def profile_state(name)
  state = {}
  cmd = Mixlib::ShellOut.new("netsh advfirewall show #{name}")
  cmd.run_command
  cmd.stdout.lines("\r\n") do |line|
    next if line.empty? || line =~ /^Ok/ || line =~ /^-/
    k, v = line.split(/\s{2,}/)
    state[k.downcase] = v.strip.downcase unless v.nil?
  end
  Chef::Log.debug("Parsed state: #{state}")
  state
end
