import dns.resolver

result = dns.resolver.query('trustbondunitybk.com', 'A')
for ipval in result:
    print('IP', ipval.to_text())

