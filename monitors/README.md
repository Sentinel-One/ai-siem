Use third party monitor with Dataset Agent

0.  install agent
1.  download monitor files `git clone https://github.com/scalyr/samples.git`
2.  copy monitor to builtin_monitors path. `cp samples/monitors/log_gen.py /usr/share/scalyr-agent-2/py/scalyr_agent/builtin_monitors`
3.  configure agent monitor `vi /etc/scalyr-agent-2/agent.log` 
```
   monitors: [
    {
            "module": "scalyr_agent.builtin_monitors.log_gen",
            "logs": "/tmp/logs/*",
            "type_array":"['cisco', 'windows_dns']",
            "parser":"json",
            "time_pattern":"(?P<date>(\\d+ \\w+ \\d+|\\d+\\/\\d+\\/\\d+)) (?P<time>(\\d{2}:\\d{2}:\\d{2}\\.\\d{3}|\\d+:\\d+:\\d+ \\w+))",
            "sampling_rate":".2"}

   ]
 ```
4.  scalyr-agent-2 start
