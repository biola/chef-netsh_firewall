#
# Cookbook Name:: netsh_firewall
# Recipe:: default
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

# Disable firewall rules that are not whitelisted or managed with Chef
# Put this in a ruby block to ensure the resource collection is complete
enabled_rules = parse_enabled_rules
ruby_block 'disable unmanaged rules' do
  block do
    resource_list = run_context.resource_collection.keys
    enabled_rules.each do |rule|
      # Ignore rules that are whitelisted
      next if node['netsh_firewall']['group_whitelist'].include? rule['Grouping']
      next if node['netsh_firewall']['rule_whitelist'].include? rule['Rule Name']
      # Ignore rules in the resource collection
      next if resource_list.include? "netsh_firewall_rule[#{rule['Rule Name']}]"
      r = Chef::Resource.resource_for_node(:netsh_firewall_rule, node).new(rule['Rule Name'], run_context)
      r.profiles rule['Profiles']
      r.run_action :disable
    end
  end
  only_if { node['netsh_firewall']['disable_unmanaged_rules'] }
end
