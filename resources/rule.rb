#
# Cookbook Name:: netsh_firewall
# Resource:: rule
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

actions :allow, :block, :disable, :enable
default_action :allow

attribute :name, kind_of: String, name_attribute: true
attribute :description, kind_of: String, default: nil
attribute :dir, kind_of: Symbol, default: :in, equal_to: [:in, :out]
attribute :localip, kind_of: String, default: 'any'
attribute :localport, kind_of: String, default: 'any'
attribute :profile, kind_of: Symbol, default: :any, equal_to: [:any, :domain, :private, :public]
attribute :program, kind_of: String, default: nil
attribute :protocol, kind_of: Symbol, default: :tcp, equal_to: [:any, :icmpv4, :icmpv6, :tcp, :udp]
attribute :remoteip, kind_of: String, default: 'any'
attribute :remoteport, kind_of: String, default: 'any'
