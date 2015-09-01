# netsh_firewall

This cookbook provides resources for managing Windows Firewall using the netsh utility. See https://technet.microsoft.com/en-us/library/Dd734783.aspx for details on configuring Windows Firewall using netsh.

## Platforms

* Windows Vista
* Windows 7
* Windows 8, 8.1
* Windows Server 2008, 2008 R2
* Windows Server 2012, 2012 R2

## Recipes

### default

If the `['netsh_firewall']['disable_unmanaged']` attribute is set to true this recipe will disable firewall rules that are not managed with Chef or whitelisted using attributes. Use at your own risk.

## Resources

### netsh_firewall_profile

#### Actions

- `:disable`: disable a firewall profile
- `:enable`: enable a firewall profile and set inbound/outbound policy; this is the default action

#### Parameters

- `name`: name attribute; specify `all`, `domain`, `private`, or `public`
- `inbound`: `:allow` or `:block` (default)
- `outbound`: `:allow` (default) or `:block`

#### Example

```ruby
netsh_firewall_profile 'all' do
  inbound :block
  outbound :allow
end
```

### netsh_firewall_rule

#### Actions

- `:allow`: create a rule to allow traffic through the firewall; this is the default action
- `:block`: create a rule to block traffic
- `:disable`: disable an existing rule (useful for built-in rules)
- `:enable`: enable an existing rule

#### Parameters

- `name`: name attribute; the name of the rule to create
- `description`: an optional description for the rule
- `dir`: `:in` (default) or `:out`; the direction of the rule
- `localip`: a comma separated list of IP addresses or subnets in CIDR notation; defaults to 'any'
- `localport`: the local port number; defaults to 'any'
- `profile`: `:any` (default), `:domain`, `:private`, or `:public`
- `program`: a path to a program; traffic generated by the program will match this rule
- `protocol`: `:tcp` (default), `:udp`, `:icmpv4`, `:icmpv6`, or `:any`
- `remoteip`: a comma separated list of IP addresses or subnets in CIDR notation; defaults to 'any'
- `remoteport`: the remote port number; defaults to 'any'

#### Examples

```ruby
netsh_firewall_rule 'Windows Remote Management (HTTPS-In)' do
  description 'Allow remote management over SSL'
  localport '5986'
  action :allow
end

netsh_firewall_rule 'Windows Remote Management (HTTP-In)' do
  action :disable
end
```

## License

Copyright 2015 Biola University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
