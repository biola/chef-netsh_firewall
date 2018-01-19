#
# Cookbook Name:: netsh_firewall
# Resource:: profile
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

property :name, %w[all domain private public], name_property: true
property :inbound, [:allow, :block], default: :block
property :outbound, [:allow, :block], default: :allow

action :enable do
  unless profile_enabled?
    shell_out!("netsh advfirewall set #{profile_name} state on")
    new_resource.updated_by_last_action(true)
  end

  if policy_needs_update?
    shell_out!("netsh advfirewall set #{profile_name} firewallpolicy #{firewall_policy}")
    new_resource.updated_by_last_action(true)
  end
end

action :disable do
  if profile_enabled?
    shell_out!("netsh advfirewall set #{profile_name} state off")
    new_resource.updated_by_last_action(true)
  end
end

def firewall_policy
  "#{inbound}inbound,#{outbound}outbound"
end

def policy_needs_update?
  if name == 'all'
    profile_state('domainprofile')['Firewall Policy'] != firewall_policy ||
      profile_state('privateprofile')['Firewall Policy'] != firewall_policy ||
      profile_state('publicprofile')['Firewall Policy'] != firewall_policy
  else
    profile_state(profile_name)['Firewall Policy'] != firewall_policy
  end
end

def profile_name
  return 'allprofiles' if name == 'all'
  "#{name}profile"
end

def profile_enabled?
  if name == 'all'
    profile_state('domainprofile')['State'] == 'on' &&
      profile_state('privateprofile')['State'] == 'on' &&
      profile_state('publicprofile')['State'] == 'on'
  else
    profile_state(profile_name)['State'] == 'on'
  end
end

# Retrieve the state of the given profile and parse the output
# Returned values are downcased to make things easier
def profile_state(name)
  state = {}
  cmd = shell_out!("netsh advfirewall show #{name}")
  cmd.stdout.lines("\r\n") do |line|
    next if line.empty? || line =~ /^Ok/ || line =~ /^-/
    k, v = line.split(/\s{2,}/)
    state[k] = v.strip.downcase unless v.nil?
  end
  state
end
