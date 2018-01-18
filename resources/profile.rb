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

actions :disable, :enable
default_action :enable

attribute :name, kind_of: String, name_attribute: true, equal_to: %w[all domain private public]
attribute :inbound, kind_of: Symbol, default: :block, equal_to: [:allow, :block]
attribute :outbound, kind_of: Symbol, default: :allow, equal_to: [:allow, :block]
