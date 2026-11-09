| union
 ( | datasource assets from 'surface/networkDiscovery' | filter assetStatus = 'Active' missingCoverage contains 'EPP' | let nm = lower(replace(name != null ? name : '', '\\..*$', ''))
| let nameOk = len(nm) >= 3 && !(nm matches '^[0-9-]+$') && !(nm matches '^([0-9a-f]{2}[:-]?){5}[0-9a-f]{2}$') && !(nm matches '^(unknown.*|localhost|iphone.*|ipad.*|watch|android.*|galaxy.*|macbook.*|imac|raspberrypi)$')
| let macKeys = array_from_json(macAddresses != null ? macAddresses : '[]').map(func(x) -> 'mac:' + replace(lower(x), '[^0-9a-f]', '')).filter(func(k) -> k matches '^mac:[0-9a-f][048c][0-9a-f]{10}$' && k != 'mac:000000000000' && k != 'mac:00059a3c7a00')
| let ipKeys = array_from_json(networkInterfaces != null ? networkInterfaces : '[]').map(func(i) -> 'ip:' + json_object_value(i, 'ip') + '@' + replace(lower(json_object_value(i, 'gatewayMac')), '[^0-9a-f]', '')).filter(func(k) -> k matches '^ip:[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+@[0-9a-f]{12}$' && !(k matches '@(00005e0001|00000c07ac|00000c9ff|123456789abc)'))
| let keys = macKeys.concat(ipKeys).concat(nameOk ? array('name:' + nm) : array()) | let key = keys.concat(array('self:' + id)).expand() | let nd = id + '|' + name + '|' + s1SiteName | columns key, nd ),
 ( | datasource assets from 'surface/endpoint' | let nm = lower(replace(name != null ? name : '', '\\..*$', ''))
| let nameOk = len(nm) >= 3 && !(nm matches '^[0-9-]+$') && !(nm matches '^([0-9a-f]{2}[:-]?){5}[0-9a-f]{2}$') && !(nm matches '^(unknown.*|localhost|iphone.*|ipad.*|watch|android.*|galaxy.*|macbook.*|imac|raspberrypi)$')
| let macKeys = array_from_json(macAddresses != null ? macAddresses : '[]').map(func(x) -> 'mac:' + replace(lower(x), '[^0-9a-f]', '')).filter(func(k) -> k matches '^mac:[0-9a-f][048c][0-9a-f]{10}$' && k != 'mac:000000000000' && k != 'mac:00059a3c7a00')
| let ipKeys = array_from_json(networkInterfaces != null ? networkInterfaces : '[]').map(func(i) -> 'ip:' + json_object_value(i, 'ip') + '@' + replace(lower(json_object_value(i, 'gatewayMac')), '[^0-9a-f]', '')).filter(func(k) -> k matches '^ip:[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+@[0-9a-f]{12}$' && !(k matches '@(00005e0001|00000c07ac|00000c9ff|123456789abc)'))
| let keys = macKeys.concat(ipKeys).concat(nameOk ? array('name:' + nm) : array()) | let key = keys.expand() | let ageDays = lastActiveDt != null ? (now() - strptime(substr(lastActiveDt, 0, 19), '%Y-%m-%dT%H:%M:%S')) / 86400000000000 : 0 | let live = assetStatus = 'Active' && activeCoverage contains 'EPP' | let ep = id + '=' + name + '@' + s1SiteName | let epAct = live && ageDays <= 30 ? ep : null, epOld = live && ageDays > 30 ? ep : null, epIn = live ? null : ep | columns key, epAct, epOld, epIn )
| group nds = array_agg_distinct(nd, 200), ndc = count(nd != null), act = array_agg_distinct(epAct, 20), old = array_agg_distinct(epOld, 20), inact = array_agg_distinct(epIn, 20) by key
| filter ndc > 0
| let shared = key matches '^mac:' && ndc > 1
| let ag = shared ? '' : act.filter(func(x) -> x != null).to_string(',')
| let og = shared ? '' : old.filter(func(x) -> x != null).to_string(',')
| let inactive = shared ? 0 : (ag == '' && og == '' && inact.filter(func(x) -> x != null).len() > 0 ? 1 : 0)
| let isMac = key matches '^mac:', isIp = key matches '^ip:', isName = key matches '^name:'
| let n = nds.expand()
| filter n != null
| group macA = array_agg_distinct(isMac && ag != '' ? ag : null, 50), ipA = array_agg_distinct(isIp && ag != '' ? ag : null, 50), nmA = array_agg_distinct(isName && ag != '' ? ag : null, 50), macO = array_agg_distinct(isMac && og != '' ? og : null, 50), ipO = array_agg_distinct(isIp && og != '' ? og : null, 50), nmO = array_agg_distinct(isName && og != '' ? og : null, 50), inactN = sum(inactive) by n
| let macAs = macA.filter(func(x) -> x != null).to_string(','), ipAs = ipA.filter(func(x) -> x != null).to_string(','), nmAs = nmA.filter(func(x) -> x != null).to_string(',')
| let macOs = macO.filter(func(x) -> x != null).to_string(','), ipOs = ipO.filter(func(x) -> x != null).to_string(','), nmOs = nmO.filter(func(x) -> x != null).to_string(',')
| let bothA = extract_matches(ipAs, '(?:^|,)([a-z0-9-]+)=').intersect(extract_matches(nmAs, '(?:^|,)([a-z0-9-]+)='))
| let bothO = extract_matches(ipOs, '(?:^|,)([a-z0-9-]+)=').intersect(extract_matches(nmOs, '(?:^|,)([a-z0-9-]+)='))
| let rank = macAs != '' ? 1 : (bothA.len() > 0 ? 2 : (macOs != '' || bothO.len() > 0 ? 5 : (nmAs != '' || nmOs != '' ? 3 : (ipAs != '' || ipOs != '' ? 4 : (inactN > 0 ? 6 : 7)))))
| let pickId = rank == 2 ? bothA.get(0) : (rank == 5 && macOs == '' ? bothO.get(0) : '')
| let agentList = rank == 1 ? macAs : (rank == 5 ? macOs : (rank == 3 ? (nmAs != '' ? nmAs : nmOs) : (rank == 4 ? (ipAs != '' ? ipAs : ipOs) : '')))
| let srcList = rank == 2 ? nmAs : nmOs
| let picked = pickId != '' ? srcList.split(',').filter(func(x) -> substr(x, 0, len(pickId) + 1) == pickId + '=').get(0) : replace(agentList, ',.*$', '')
| let agent = replace(picked, '^[a-z0-9-]+=', '')
| let verdict = rank == 1 ? 'Likely false positive: agent MAC matches' : (rank == 2 ? 'Likely false positive: agent IP and hostname match' : (rank == 3 ? 'Review: hostname matches an agent' : (rank == 4 ? 'Review: IP matches an agent' : (rank == 5 ? 'Review: matched agent has been offline' : (rank == 6 ? 'Unprotected: matched agent is not active' : 'Unprotected: no agent match')))))
| columns device = n, verdict, agent, rank
| sort rank
| limit 20000
